const {
    USERNAME_INPUT_TYPES, autocompleteTokens, credentialFields, credentialScope,
    hasSearchHint, hasUsernameHint, inputDescriptors, isCredentialInput,
    isElementVisible, isLoginPasswordInput, isNewPasswordInput, isTotpInput,
    isUsableInput, scopeInputs, usernameCandidates
} = PasswordManagerContentDetection;

function getDomainFromUrl(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.origin.toLowerCase();
    } catch {
        return url;
    }
}

let modalOpen = false;
let popupResolved = false;
let credentialAttemptPending = false;
let credentialUserIntent = false;

// ===============================
// Request credentials from background
// ===============================
async function initExtension() {
    await restoreUsernameFromPreviousStep();

    // Do not place plaintext vault credentials in every matching page at load.
    // Only the secure picker delivers a selected vault secret.
    observeInputs();

    // Remember the last username typed on this domain so password-only
    // login steps (and the save prompt) know which account is logging in.
    document.addEventListener("input", (e) => {
        const t = e.target;
        if (!e.isTrusted || !(t instanceof HTMLInputElement) || !isCredentialInput(t)) return;
        credentialUserIntent = true;
        lastCredentialInput = t;
        if (USERNAME_INPUT_TYPES.has(t.type) && t.value.trim()) {
            storeUsernameForLater(t.value.trim());
        }
    }, true);

    document.addEventListener("focusin", (e) => {
        if (e.target instanceof HTMLInputElement && isCredentialInput(e.target)) {
            lastCredentialInput = e.target;
        }
    }, true);

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
    document.addEventListener("submit", event => {
        if (event.isTrusted && navigator.userActivation?.isActive === true
            && event.target instanceof HTMLFormElement) {
            const username = usernameFromScope(event.target);
            if (username) rememberUsernameAcrossNavigation(username);
        }
        submissionCoordinator.onSubmit(event).catch(error => {
            console.log("Password Manager submission error:", error);
        });
    }, true);

    // Multi-step login pages frequently use a type=button or a scripted
    // control to swap the password step for TOTP without submitting a form or
    // navigating. Capture the credential snapshot before that handler clears
    // or removes the password input, then defer just long enough for a normal
    // submit event to take ownership when one exists.
    const handlePossibleAdvance = source => {
        const input = source instanceof HTMLInputElement && isCredentialInput(source)
            ? source
            : lastCredentialInput;
        const scope = source?.form
            || source?.closest?.("form, [role='form'], dialog")
            || (input ? credentialScope(input) : null);
        if (!scope) return;
        credentialUserIntent = true;
        const username = usernameFromScope(scope);
        const credentials = credentialsFromScope(scope);
        PasswordManagerFormSubmission.scheduleCredentialAdvance({
            username: username || credentials.username,
            password: credentials.password
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

    document.addEventListener("click", event => {
        if (!event.isTrusted || !(event.target instanceof Element)) return;
        const control = event.target.closest(
            "button, input[type='button'], input[type='submit'], input[type='image'], [role='button']"
        );
        if (!control || control.classList.contains("my-extension-ui")) return;
        handlePossibleAdvance(control);
    }, true);

    document.addEventListener("keydown", event => {
        if (!event.isTrusted || event.key !== "Enter" || event.isComposing) return;
        if (!(event.target instanceof HTMLInputElement) || !isCredentialInput(event.target)) return;
        handlePossibleAdvance(event.target);
    }, true);

    // Catch logins that navigate/redirect without a form submit event
    // (e.g. fetch + window.location, or form.submit() in JS). The extension
    // window and background-owned operation survive the page being destroyed.
    window.addEventListener("pagehide", event => {
        if (!event.isTrusted || !credentialUserIntent) return;
        if (modalOpen || popupResolved || credentialAttemptPending) return;

        const { username: rawUsername, password } = findLoginCredentials();
        if (!password) {
            const username = lastCredentialInput
                ? usernameFromScope(credentialScope(lastCredentialInput))
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
    });
}

initExtension().catch(error => console.log("Password Manager error:", error));
