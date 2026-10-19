"use strict";
const detection = require("./content_detection.js");
const PasswordManagerFormSubmission = require("./form_submission.js");
const bridgeModule = require("./content_bridge.js");
const credentialsModule = require("./content_credentials.js");
const autofillModule = require("./content_autofill.js");
const controlsModule = require("./content_controls.js");
const generatorModule = require("./content_generator.js");
const observerModule = require("./content_observer.js");
const duoModule = require("./content_duo.js");
module.exports.create = function create() {
    const { USERNAME_INPUT_TYPES, isCredentialInput, credentialScope } = detection;
    const lifecycle = new AbortController();
    const rootControllers = new Map();
    const handledEvents = new WeakSet();
    let disposed = false;
    const bridge = bridgeModule.create();
    const credentials = credentialsModule.create({ roots: () => rootControllers.keys() });
    const { restoreUsernameFromPreviousStep, storeUsernameForLater, rememberUsernameAcrossNavigation,
        findLoginCredentials, usernameFromScope, credentialsFromScope, resolveUsername } = credentials;
    const { openCredentialPrompt } = bridge;
    const autofill = autofillModule.create({ bridge });
    const controls = controlsModule.create({ bridge, credentials, autofill });
    const generator = generatorModule.create({ controls, bridge, credentials });
    const observer = observerModule.create({ controls, generator, autofill, onRoot: registerRoot, onRemoveRoot: unregisterRoot });
    const duo = duoModule.create();
    function listen(root, type, handler) {
        root.addEventListener(type, event => {
            if (handledEvents.has(event)) return;
            handledEvents.add(event); handler(event);
        }, { capture: true, signal: rootControllers.get(root).signal });
    }
    function unregisterRoot(root) { rootControllers.get(root)?.abort(); rootControllers.delete(root); }
    function registerRoot(root) {
        if (disposed || rootControllers.has(root)) return;
        rootControllers.set(root, new AbortController());
        // Remember the last username typed on this domain so password-only
        // login steps (and the save prompt) know which account is logging in.
        listen(root, "input", (e) => {
            const t = e.composedPath?.()[0] || e.target;
            if (!e.isTrusted || !(t instanceof HTMLInputElement) || !isCredentialInput(t)) return;
            credentialUserIntent = true;
            credentials.lastInput = t;
            if (USERNAME_INPUT_TYPES.has(t.type) && t.value.trim()) {
                storeUsernameForLater(t.value.trim());
            }
        });

        listen(root, "focusin", (e) => {
            const target = e.composedPath?.()[0] || e.target;
            const targetRoot = target.getRootNode?.();
            if (targetRoot?.host && !rootControllers.has(targetRoot)) observer.scan(targetRoot);
            if (target instanceof HTMLInputElement && isCredentialInput(target)) {
                credentials.lastInput = target;
            }
        });

        const submissionCoordinator = PasswordManagerFormSubmission.createSubmissionCoordinator({
            isForm: form => form instanceof HTMLFormElement,
            credentialsFor: form => findLoginCredentials(form),
            shouldIgnore: () => credentialAttemptPending || modalOpen || popupResolved,
            userActivated: () => navigator.userActivation?.isActive === true,
            handle: async ({ credentials }) => {
                credentialAttemptPending = true;
                const { username: rawUsername, password } = credentials;
                try {
                    const username = resolveUsername(rawUsername);
                    if (rawUsername) rememberUsernameAcrossNavigation(rawUsername);

                    modalOpen = true;
                    try {
                        const result = await openCredentialPrompt(username, password);
                        if (result.action !== "skipped") popupResolved = true;
                    } finally {
                        modalOpen = false;
                    }
                } finally {
                    credentialAttemptPending = false;
                }
            }
        });
        listen(root, "submit", event => {
            if (event.isTrusted && navigator.userActivation?.isActive === true
                && event.target instanceof HTMLFormElement) {
                const username = usernameFromScope(event.target);
                if (username) rememberUsernameAcrossNavigation(username);
            }
            submissionCoordinator.onSubmit(event).catch(error => {
                console.log("Password Manager submission error:", error);
            });
        });

        // Multi-step login pages frequently use a type=button or a scripted
        // control to swap the password step for TOTP without submitting a form or
        // navigating. Capture the credential snapshot before that handler clears
        // or removes the password input, then defer just long enough for a normal
        // submit event to take ownership when one exists.
        const handlePossibleAdvance = source => {
            const input = source instanceof HTMLInputElement && isCredentialInput(source)
                ? source
                : credentials.lastInput;
            const scope = source?.form
                || source?.closest?.("form, [role='form'], dialog")
                || (input ? credentialScope(input) : null);
            if (!scope) return;
            credentialUserIntent = true;
            const username = usernameFromScope(scope);
            const snapshot = credentialsFromScope(scope);
            PasswordManagerFormSubmission.scheduleCredentialAdvance({
                username: username || snapshot.username,
                password: snapshot.password
            }, {
                remember: rememberUsernameAcrossNavigation,
                shouldIgnore: () => credentialAttemptPending || modalOpen || popupResolved,
                prompt: captured => {
                    credentialAttemptPending = true;
                    const resolvedUsername = resolveUsername(captured.username);
                    openCredentialPrompt(resolvedUsername, captured.password)
                        .then(result => { if (result.action !== "skipped") popupResolved = true; })
                        .catch(error => console.log("Password Manager credential prompt error:", error))
                        .finally(() => { credentialAttemptPending = false; });
                }
            });
        };

        listen(root, "click", event => {
            const target = event.composedPath?.()[0] || event.target;
            if (!event.isTrusted || !(target instanceof Element)) return;
            const control = target.closest(
                "button, input[type='button'], input[type='submit'], input[type='image'], [role='button']"
            );
            if (!control || control.classList.contains("my-extension-ui")) return;
            handlePossibleAdvance(control);
        });

        listen(root, "keydown", event => {
            if (!event.isTrusted || event.key !== "Enter" || event.isComposing) return;
            const target = event.composedPath?.()[0] || event.target;
            if (!(target instanceof HTMLInputElement) || !isCredentialInput(target)) return;
            handlePossibleAdvance(target);
        });

    }
    let modalOpen = false;
    let popupResolved = false;
    let credentialAttemptPending = false;
    let credentialUserIntent = false;

    // ===============================
    // Request credentials from background
    // ===============================
    async function start() {
        await restoreUsernameFromPreviousStep();
        if (disposed) return;

        // Do not place plaintext vault credentials in every matching page at load.
        // Only the secure picker delivers a selected vault secret.
        observer.observeInputs();

        // Catch logins that navigate/redirect without a form submit event
        // (e.g. fetch + window.location, or form.submit() in JS). The extension
        // window and background-owned operation survive the page being destroyed.
        window.addEventListener("pagehide", event => {
            if (!event.isTrusted || !credentialUserIntent) return;
            if (modalOpen || popupResolved || credentialAttemptPending) return;

            const { username: rawUsername, password } = findLoginCredentials();
            if (!password) {
                const username = credentials.lastInput
                    ? usernameFromScope(credentialScope(credentials.lastInput))
                    : "";
                if (username) rememberUsernameAcrossNavigation(username);
                return;
            }
            const username = resolveUsername(rawUsername);
            if (rawUsername) storeUsernameForLater(rawUsername);

            chrome.runtime.sendMessage(
                { action: "openCredentialPrompt", username, password },
                () => void chrome.runtime.lastError
            );
        }, { signal: lifecycle.signal });
    }


    function dispose() {
        if (disposed) return;
        disposed = true; lifecycle.abort(); observer.dispose();
        generator.dispose(); controls.dispose(); bridge.dispose(); duo.dispose(); credentials.dispose();
    }
    return { start, dispose, roots: () => [...rootControllers.keys()] };
};
