(function (root, factory) {
    const api = factory();
    root.PasswordManagerFormSubmission = api;
    if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    "use strict";

    function createSubmissionCoordinator(options) {
        const resumedForms = new WeakSet();

        async function onSubmit(event) {
            const form = event.target;
            if (!options.isForm(form)) return;
            if (resumedForms.delete(form)) return;

            const credentials = options.credentialsFor(form);
            if (!credentials.password || options.shouldIgnore()) return;

            // This must run before the first await in this function.
            event.preventDefault();
            try {
                await options.handle({
                    form,
                    submitter: event.submitter,
                    credentials
                });
            } finally {
                resumedForms.add(form);
                options.resume(form, event.submitter, resumedForms);
            }
        }

        return { onSubmit };
    }

    return { createSubmissionCoordinator };
});
