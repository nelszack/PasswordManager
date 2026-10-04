// Use the native value setter and input/change events to synchronize form frameworks.
function fillInput(input, value) {
    if (!input || !isUsableInput(input)) return;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    if (setter) setter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
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
