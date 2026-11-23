(function (root, factory) {
    const api = factory();
    if (typeof module === "object" && module.exports) module.exports = api;
    else root.PasswordManagerFormSubmission = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    "use strict";

    // All submission sources share one document-wide decision lifecycle.
    function createCredentialAttempt(open) {
        let phase = "idle";
        function reserve() {
            if (phase !== "idle") return false;
            phase = "pending";
            return true;
        }
        async function run(credentials) {
            if (!reserve()) return;
            try {
                const result = await open(credentials);
                if (phase !== "disposed") phase = result.action === "skipped" ? "idle" : "resolved";
            } finally {
                if (phase === "pending") phase = "idle";
            }
        }
        return {
            run,
            reserve,
            get idle() {
                return phase === "idle";
            },
            dispose() {
                phase = "disposed";
            },
        };
    }

    function createSubmissionCoordinator(options) {
        const pendingForms = new WeakSet();

        async function onSubmit(event) {
            const form = event.target;
            if (!options.isForm(form) || !event.isTrusted || !options.userActivated()) return;
            if (pendingForms.has(form) || options.shouldIgnore()) return;
            const credentials = options.credentialsFor(form);
            if (!credentials.password) return;

            // Snapshot and send before navigation, but never cancel/replay the
            // site's submission or wait for a password-dependent result.
            pendingForms.add(form);
            try {
                await options.handle({ form, submitter: event.submitter, credentials });
            } finally {
                pendingForms.delete(form);
            }
        }

        return { onSubmit };
    }

    // Submit controls and Enter advance a login at once. Other buttons also open
    // menus or reveal passwords, so with options.advanced the snapshot is offered
    // only once the page leaves the password step (options.advanced() returns true)
    // within the confirmation window. The caller confirms or cancels the returned
    // watch on page hide.
    function scheduleCredentialAdvance(credentials, options) {
        if (credentials.username) options.remember(credentials.username);
        if (!credentials.password) return null;
        const prompt = () => {
            if (!options.shouldIgnore()) options.prompt(credentials);
        };
        if (!options.advanced) {
            (options.defer || queueMicrotask)(prompt);
            return null;
        }
        const {
            setTimeout: schedule = globalThis.setTimeout,
            clearTimeout: unschedule = globalThis.clearTimeout,
            now = Date.now,
            // Long enough for a sign-in request to return before the page
            // swaps the step; buttons that leave the step stay put meanwhile.
            confirmWithinMs = 3000,
            intervalMs = 100,
        } = options;
        const deadline = now() + confirmWithinMs;
        let timer = null;
        let settled = false;
        function finish(confirmed) {
            if (settled) return;
            settled = true;
            unschedule(timer);
            if (confirmed) prompt();
        }
        function poll() {
            if (settled) return;
            if (options.advanced()) finish(true);
            else if (now() >= deadline) finish(false);
            else timer = schedule(poll, intervalMs);
        }
        timer = schedule(poll, 0);
        return {
            credentials,
            get pending() {
                return !settled;
            },
            confirm: () => finish(true),
            cancel: () => finish(false),
        };
    }

    return { createCredentialAttempt, createSubmissionCoordinator, scheduleCredentialAdvance };
});
