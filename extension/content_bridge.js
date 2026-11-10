"use strict";
const { isUsableInput } = require("./content_detection.js");

module.exports.create = function create({} = {}) {
    let disposed = false;
    // Use the native value setter and input/change events to synchronize form frameworks.
    function fillInput(input, value) {
        if (!input || !isUsableInput(input)) return;
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
        if (setter) setter.call(input, value);
        else input.value = value;
        input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
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
                const request = { token: null, timer: null, finish(value, error) {
                    if (!active.delete(request)) return;
                    opening.delete(request);
                    if (request.token) resolvers.delete(request.token);
                    clearTimeout(request.timer);
                    if (!opening.size) early.clear();
                    if (error) reject(error); else resolve(value);
                } };
                opening.add(request); active.add(request);
                try {
                    chrome.runtime.sendMessage({ action, ...fields }, response => {
                        if (!active.has(request)) return;
                        if (chrome.runtime.lastError) {
                            request.finish(null, new Error(chrome.runtime.lastError.message));
                            return;
                        }
                        if (response?.skipped) { request.finish({ action: "skipped" }); return; }
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
                } catch (error) { request.finish(null, error); }
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
    const listener = message => { pickers.receive(message); prompts.receive(message); };
    chrome.runtime.onMessage.addListener(listener);
    function dispose() {
        disposed = true;
        chrome.runtime.onMessage.removeListener(listener);
        pickers.dispose(); prompts.dispose();
    }

    return { fillInput, openSecurePicker: kind => pickers.open({ kind }),
        openCredentialPrompt: (username, password) => prompts.open({ username, password }), dispose };
};
