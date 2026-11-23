"use strict";
const { isUsableInput } = require("./content_detection.js");

const { setControlValue } = require("./content_value.js");

// An extension update or reload leaves this script running with a dead runtime.
function contextInvalidated(error) {
    return /extension context invalidated/i.test(String(error?.message || error || ""));
}
module.exports.contextInvalidated = contextInvalidated;

module.exports.create = function create({ onInvalidated = () => {} } = {}) {
    let disposed = false;
    // Use the native value setter and input/change events to synchronize form frameworks.
    function fillInput(input, value) {
        if (!input || !isUsableInput(input)) return;
        setControlValue(input, value);
    }

    // Result delivery and the opening callback use separate Chrome message
    // channels. A fast selection/cancellation can arrive before its callback.
    function windowRequests(action, resultAction, timeout, cancelled) {
        const opening = new Set();
        const active = new Set();
        const resolvers = new Map();
        const early = new Map();
        function open(fields) {
            if (disposed) return Promise.resolve(cancelled);
            return new Promise((resolve, reject) => {
                const request = {
                    token: null,
                    timer: null,
                    finish(value, error) {
                        if (!active.delete(request)) return;
                        opening.delete(request);
                        if (request.token) resolvers.delete(request.token);
                        clearTimeout(request.timer);
                        if (!opening.size) early.clear();
                        if (error) reject(error);
                        else resolve(value);
                    },
                };
                opening.add(request);
                active.add(request);
                try {
                    chrome.runtime.sendMessage({ action, ...fields }, response => {
                        if (!active.has(request)) return;
                        if (chrome.runtime.lastError) {
                            request.finish(null, new Error(chrome.runtime.lastError.message));
                            return;
                        }
                        if (response?.skipped) {
                            request.finish({ action: "skipped" });
                            return;
                        }
                        if (!response?.success || !response.token) {
                            request.finish(null, new Error(response?.error || "Could not open secure window"));
                            return;
                        }
                        request.token = response.token;
                        opening.delete(request);
                        if (early.has(request.token)) {
                            const value = early.get(request.token);
                            early.delete(request.token);
                            request.finish(value);
                        } else {
                            resolvers.set(request.token, value => request.finish(value));
                            request.timer = setTimeout(() => request.finish(cancelled), timeout);
                        }
                        if (!opening.size) early.clear();
                    });
                } catch (error) {
                    request.finish(null, error);
                    if (contextInvalidated(error)) onInvalidated();
                }
            });
        }
        function receive(message) {
            if (message.action !== resultAction) return;
            const value = action === "openSecurePicker" ? message.payload : message.result;
            const resolver = resolvers.get(message.token);
            if (resolver) resolver(value);
            else if (typeof message.token === "string" && opening.size && early.size < opening.size) {
                early.set(message.token, value);
            }
        }
        function dispose() {
            for (const request of active) request.finish(cancelled);
            early.clear();
        }
        return { open, receive, dispose };
    }

    const pickers = windowRequests("openSecurePicker", "securePickerResult", 65_000, null);
    const prompts = windowRequests("openCredentialPrompt", "credentialPromptResult", 125_000, { action: "cancel" });
    const listener = message => {
        pickers.receive(message);
        prompts.receive(message);
    };
    chrome.runtime.onMessage.addListener(listener);
    function dispose() {
        disposed = true;
        chrome.runtime.onMessage.removeListener(listener);
        pickers.dispose();
        prompts.dispose();
    }

    return {
        fillInput,
        openSecurePicker: kind => pickers.open({ kind }),
        openCredentialPrompt: (username, password) => prompts.open({ username, password }),
        // Fetch a login the toolbar popup asked this page to fill.
        claimPopupFill: token =>
            new Promise((resolve, reject) => {
                try {
                    chrome.runtime.sendMessage({ action: "claimPopupFill", token }, response => {
                        if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
                        else if (!response?.success) reject(new Error(response?.error || "Could not fill"));
                        else resolve(response.payload);
                    });
                } catch (error) {
                    reject(error);
                }
            }),
        dispose,
    };
};
