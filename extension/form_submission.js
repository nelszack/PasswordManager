(function (root, factory) {
    const api = factory();
    root.PasswordManagerFormSubmission = api;
    if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    "use strict";

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

    function scheduleCredentialAdvance(credentials, options) {
        if (credentials.username) options.remember(credentials.username);
        if (!credentials.password) return;
        (options.defer || queueMicrotask)(() => {
            if (!options.shouldIgnore()) options.prompt(credentials);
        });
    }

    return { createSubmissionCoordinator, scheduleCredentialAdvance };
});
