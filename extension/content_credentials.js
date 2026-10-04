let storedUsername = "";
let storedDomain = "";
let lastCredentialInput = null;

function credentialsFromScope(scope) {
    const fields = scopeInputs(scope);
    const filledPasswords = fields.filter(field =>
        isUsableInput(field) && field.type === "password" && field.value
    );
    const newPasswords = filledPasswords.filter(isNewPasswordInput);
    const currentPasswords = filledPasswords.filter(field => !isNewPasswordInput(field));
    // Capture a newly chosen password on registration/change-password forms,
    // but never autofill these fields (credentialFields excludes them).
    const passwordField = newPasswords.find(field => autocompleteTokens(field).includes("new-password"))
        || newPasswords.find(field => !inputDescriptors(field).some(value => /confirm|repeat|retype/i.test(value)))
        || newPasswords[0]
        || currentPasswords.find(field => autocompleteTokens(field).includes("current-password"))
        || currentPasswords[0]
        || null;
    if (!passwordField) return { username: "", password: "", scope };

    const candidates = usernameCandidates(fields);
    const preceding = candidates.filter(field => fields.indexOf(field) < fields.indexOf(passwordField));
    const pool = preceding.length > 0 ? preceding : candidates;
    const valued = pool.filter(field => field.value.trim());
    const usernameField = valued.find(field => autocompleteTokens(field).some(token => token === "username" || token === "email"))
        || valued.find(hasUsernameHint)
        || valued.at(-1)
        || null;

    return {
        username: usernameField ? usernameField.value.trim() : "",
        password: passwordField.value,
        scope
    };
}

function usernameFromScope(scope) {
    const fields = scopeInputs(scope);
    const candidates = usernameCandidates(fields).filter(field => field.value.trim());
    const usernameField = candidates.find(field =>
        autocompleteTokens(field).some(token => token === "username" || token === "email")
    ) || candidates.find(hasUsernameHint) || candidates.at(-1) || null;
    return usernameField ? usernameField.value.trim() : "";
}

function findLoginCredentials(source = null) {
    if (source instanceof HTMLFormElement) {
        return credentialsFromScope(source);
    }
    if (source instanceof HTMLInputElement) {
        return credentialsFromScope(credentialScope(source));
    }

    if (lastCredentialInput && lastCredentialInput.isConnected) {
        const recent = credentialsFromScope(credentialScope(lastCredentialInput));
        if (recent.password) return recent;
    }

    const seen = new Set();
    for (const passwordField of document.querySelectorAll("input[type='password']")) {
        if (!isUsableInput(passwordField) || !passwordField.value) continue;
        const scope = credentialScope(passwordField);
        if (seen.has(scope)) continue;
        seen.add(scope);
        const credentials = credentialsFromScope(scope);
        if (credentials.password) return credentials;
    }

    return { username: "", password: "", scope: null };
}

function storeUsernameForLater(username) {
    if (username) {
        storedUsername = username;
        storedDomain = getDomainFromUrl(window.location.href);
    } else {
        storedUsername = "";
        storedDomain = "";
    }
}

function rememberUsernameAcrossNavigation(username) {
    storeUsernameForLater(username);
    if (!username || window !== window.top) return;
    chrome.runtime.sendMessage({
        action: "setPendingCredentials",
        pending: { username, password: "" }
    }, () => void chrome.runtime.lastError);
}

function restoreUsernameFromPreviousStep() {
    if (window !== window.top) return Promise.resolve();
    return new Promise(resolve => {
        chrome.runtime.sendMessage({ action: "consumePendingCredentials" }, response => {
            if (!chrome.runtime.lastError && response?.success && response.pending?.username) {
                storeUsernameForLater(String(response.pending.username));
            }
            resolve();
        });
    });
}

// On password-only logins the username field may be missing; fall back to
// the last username typed on this origin.
function resolveUsername(username) {
    if (username) return username;
    if (storedUsername && storedDomain === getDomainFromUrl(window.location.href)) {
        return storedUsername;
    }
    return "";
}

// The add/update prompt is an extension-owned window so it survives page
// navigation. The background retains the password and performs the operation.
