(function (root, factory) {
    const api = factory();
    root.PasswordManagerFormSubmission = api;
    if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    "use strict";

    function createSubmissionCoordinator(options) {
        const resumedForms = new WeakSet();
        const pendingForms = new WeakSet();

        async function onSubmit(event) {
            const form = event.target;
            if (!options.isForm(form)) return;
            if (resumedForms.delete(form)) return;
            if (!event.isTrusted) return;

            // A double click can dispatch another submit event while the
            // credential prompt for this form is still open. Keep that event
            // from navigating away, but do not open a second prompt.
            if (pendingForms.has(form)) {
                event.preventDefault();
                return;
            }

            const credentials = options.credentialsFor(form);
            if (!credentials.password || options.shouldIgnore()) return;

            // This must run before the first await in this function.
            event.preventDefault();
            pendingForms.add(form);
            try {
                await options.handle({
                    form,
                    submitter: event.submitter,
                    credentials
                });
            } finally {
                pendingForms.delete(form);
                resumedForms.add(form);
                options.resume(form, event.submitter, resumedForms);
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
