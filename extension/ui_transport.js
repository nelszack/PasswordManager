"use strict";
var PasswordManagerUiTransport = (() => {
    // Transport failures are data so every view can present its own recovery UI.
    // Never retry: a disconnected mutation may already have committed.
    function send(message) {
        return new Promise(resolve => {
            try {
                chrome.runtime.sendMessage(message, response => {
                    const error = chrome.runtime.lastError;
                    resolve(error ? { success: false, error: error.message }
                        : response || { success: false, error: "Could not contact the extension worker" });
                });
            } catch (error) {
                resolve({ success: false, error: error.message });
            }
        });
    }
    async function request(message, fallback) {
        const response = await send(message);
        if (!response.success) throw new Error(response.error || fallback);
        return response;
    }
    return { send, request };
})();
if (typeof module !== "undefined") module.exports = PasswordManagerUiTransport;
