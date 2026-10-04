// Own state per worker instance; browser services are supplied by background.js.
const PasswordManagerBackgroundPending = {
    create({ chrome, security, records, setTimeout }) {
        const pendingCredentialMemory = new Map();
        function setPendingCredentials(request, sender, sendResponse) {
            const key = security.pendingStorageKey(sender);
            const domain = security.senderOrigin(sender);
            const pending = request.pending;
            if (!key || !domain || !pending || typeof pending.password !== "string") {
                sendResponse({ success: false, error: "Invalid pending credentials" });
                return;
            }
            const record = records.create(pending, domain);
            pendingCredentialMemory.set(key, record);
            setTimeout(() => {
                if (pendingCredentialMemory.get(key) === record) {
                    pendingCredentialMemory.delete(key);
                }
            }, 60_000);
            chrome.storage.session.set({ [key]: record }, () => sendResponse(chrome.runtime.lastError
                ? { success: false, error: chrome.runtime.lastError.message }
                : { success: true }));
        }

        function consumePendingCredentials(sender, sendResponse) {
            const key = security.pendingStorageKey(sender);
            const domain = security.senderOrigin(sender);
            if (!key || !domain) {
                sendResponse({ success: false, error: "Invalid page origin" });
                return;
            }
            const remembered = pendingCredentialMemory.get(key) || null;
            chrome.storage.session.get(key, result => {
                const error = chrome.runtime.lastError?.message;
                const pending = remembered || result?.[key] || null;
                chrome.storage.session.remove(key, () => void chrome.runtime.lastError);
                if (error) sendResponse({ success: false, error });
                else if (records.usable(pending, domain)) {
                    sendResponse({ success: true, pending });
                } else {
                    sendResponse({ success: true, pending: null });
                }
            });
        }

        function clearPendingCredentials(sender, sendResponse) {
            const key = security.pendingStorageKey(sender);
            if (!key) {
                sendResponse({ success: false, error: "Invalid tab" });
                return;
            }
            pendingCredentialMemory.delete(key);
            chrome.storage.session.remove(key, () => sendResponse(chrome.runtime.lastError
                ? { success: false, error: chrome.runtime.lastError.message }
                : { success: true }));
        }

        function takeRemembered(sender) {
            const key = security.pendingStorageKey(sender);
            const remembered = key ? pendingCredentialMemory.get(key) : null;
            if (key) pendingCredentialMemory.delete(key);
            return remembered;
        }

        return { set: setPendingCredentials, consume: consumePendingCredentials, clear: clearPendingCredentials, takeRemembered };
    }
};

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundPending;
