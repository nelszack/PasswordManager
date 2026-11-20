// Extension-owned decision windows (pickers, save prompts, Duo): each shows one
// pending decision identified by a token. This owns opening the window, the
// window-to-decision registry and the expiry timer; services own their state.
const PasswordManagerDecisionWindows = {
    create({ chrome, page, width, height, setTimeout, unavailable = "Could not open window" }) {
        const registry = new Map();

        function close(windowId) {
            if (Number.isInteger(windowId)) chrome.windows.remove(windowId, () => void chrome.runtime.lastError);
        }

        // Resolves with the new window's ID once it is registered for `value`, or
        // with null when isCurrent() reports that the decision ended while the
        // browser opened it (that window is closed). Rejects when no window opened.
        // onExpire runs at expiresAt.
        function open(token, value, { isCurrent, expiresAt, onExpire }) {
            return new Promise((resolve, reject) => {
                chrome.windows.create(
                    {
                        url: chrome.runtime.getURL(`${page}?token=${encodeURIComponent(token)}`),
                        type: "popup",
                        width,
                        height,
                        focused: true,
                    },
                    window => {
                        const error = chrome.runtime.lastError?.message;
                        if (error || !Number.isInteger(window?.id)) {
                            reject(new Error(error || unavailable));
                            return;
                        }
                        if (!isCurrent()) {
                            close(window.id);
                            resolve(null);
                            return;
                        }
                        registry.set(window.id, value);
                        if (onExpire) setTimeout(onExpire, Math.max(0, expiresAt - Date.now()));
                        resolve(window.id);
                    }
                );
            });
        }

        // Stop tracking a window; returns the decision it showed, if any.
        function release(windowId) {
            const value = registry.get(windowId);
            registry.delete(windowId);
            return value;
        }

        return { open, close, release, has: windowId => registry.has(windowId) };
    },
};

if (typeof module !== "undefined") module.exports = PasswordManagerDecisionWindows;
