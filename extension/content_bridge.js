// Use the native value setter and input/change events to synchronize form frameworks.
function fillInput(input, value) {
    if (!input || !isUsableInput(input)) return;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    if (setter) setter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
}

// Fetch the current saved accounts for a domain from the background
function fetchAccounts(domain) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage(
            { action: "getCredentials", domain: domain },
            (response) => {
                let accounts = [];
                if (response && response.success) {
                    try {
                        accounts = JSON.parse(response.data);
                        if (!Array.isArray(accounts)) accounts = [];
                    } catch (e) {
                        accounts = [];
                    }
                }
                resolve(accounts);
            }
        );
    });
}

// Card and identity data is fetched only after the user opens its picker.
// This avoids placing unrelated plaintext vault items into every page at load.
function fetchAutofillItems() {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: "getAutofillItems" }, (response) => {
            let items = [];
            if (response && response.success) {
                try {
                    items = JSON.parse(response.data);
                    if (!Array.isArray(items)) items = [];
                } catch {
                    items = [];
                }
            }
            resolve(items);
        });
    });
}

function fetchAutofillItem(id) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: "getAutofillItem", id }, (response) => {
            if (chrome.runtime.lastError || !response?.success) return resolve(null);
            try {
                const item = JSON.parse(response.data);
                resolve(item && item.id === id ? item : null);
            } catch (_) {
                resolve(null);
            }
        });
    });
}

function fetchTotp(id) {
    return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({ action: "getTotp", id }, (response) => {
            if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
            } else if (!response?.success) {
                reject(new Error(response?.error || "TOTP unavailable"));
            } else {
                resolve(response.data);
            }
        });
    });
}

const securePickerResolvers = new Map();
const credentialPromptResolvers = new Map();

function openSecurePicker(kind) {
    return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({ action: "openSecurePicker", kind }, response => {
            if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
                return;
            }
            if (!response?.success || !response.token) {
                reject(new Error(response?.error || "Could not open secure picker"));
                return;
            }
            const timer = setTimeout(() => {
                securePickerResolvers.delete(response.token);
                resolve(null);
            }, 65_000);
            securePickerResolvers.set(response.token, payload => {
                clearTimeout(timer);
                resolve(payload);
            });
        });
    });
}

function openCredentialPrompt(username, password) {
    return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({ action: "openCredentialPrompt", username, password }, response => {
            if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
                return;
            }
            if (response?.matched) {
                resolve({ action: "matched" });
                return;
            }
            if (response?.skipped) {
                resolve({ action: "skipped" });
                return;
            }
            if (!response?.success || !response.token) {
                reject(new Error(response?.error || "Could not open credential prompt"));
                return;
            }
            const timer = setTimeout(() => {
                credentialPromptResolvers.delete(response.token);
                resolve({ action: "cancel" });
            }, 125_000);
            credentialPromptResolvers.set(response.token, result => {
                clearTimeout(timer);
                resolve(result);
            });
        });
    });
}

chrome.runtime.onMessage.addListener(message => {
    if (message.action === "securePickerResult") {
        const resolver = securePickerResolvers.get(message.token);
        if (!resolver) return;
        securePickerResolvers.delete(message.token);
        resolver(message.payload);
    } else if (message.action === "credentialPromptResult") {
        const resolver = credentialPromptResolvers.get(message.token);
        if (!resolver) return;
        credentialPromptResolvers.delete(message.token);
        resolver(message.result);
    }
});
