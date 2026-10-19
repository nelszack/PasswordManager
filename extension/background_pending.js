// Serialize operations per tab so consumption, replacement and expiry cannot race.
const PasswordManagerBackgroundPending = {
    create({ chrome, security, records, setTimeout }) {
        const memory = new Map(), operations = new Map();
        const prefix = "pmPopupPending:";
        function storage(method, value) {
            return new Promise((resolve, reject) => chrome.storage.session[method](value, result => {
                const error = chrome.runtime.lastError?.message;
                if (error) reject(new Error(error)); else resolve(result);
            }));
        }
        function ordered(key, operation) {
            const previous = operations.get(key) || Promise.resolve();
            const next = previous.catch(() => {}).then(operation);
            operations.set(key, next);
            next.finally(() => { if (operations.get(key) === next) operations.delete(key); }).catch(() => {});
            return next;
        }
        function respond(operation, sendResponse) {
            operation.then(sendResponse, error => sendResponse({ success: false, error: error.message }));
        }
        function expire(key) {
            return ordered(key, async () => {
                const result = await storage("get", key);
                const record = result?.[key];
                if (record && !records.usable(record, record.domain)) await storage("remove", key);
                const remembered = memory.get(key);
                if (remembered && !records.usable(remembered, remembered.domain)) memory.delete(key);
            });
        }
        function set(request, sender, sendResponse) {
            const key = security.pendingStorageKey(sender), domain = security.senderOrigin(sender);
            const pending = request?.pending;
            if (!key || !domain || !pending || "password" in pending
                || typeof pending.username !== "string" || !pending.username || pending.username.length > 4096) {
                sendResponse({ success: false, error: "Invalid pending credentials" }); return;
            }
            const record = records.create(pending, domain);
            respond(ordered(key, async () => {
                await storage("set", { [key]: record });
                memory.set(key, record);
                setTimeout(() => { expire(key).catch(() => {}); }, records.MAX_AGE_MS);
                return { success: true };
            }), sendResponse);
        }
        function consume(sender, sendResponse) {
            const key = security.pendingStorageKey(sender), domain = security.senderOrigin(sender);
            if (!key || !domain) { sendResponse({ success: false, error: "Invalid page origin" }); return; }
            respond(ordered(key, async () => {
                const result = await storage("get", key);
                const pending = memory.get(key) || result?.[key] || null;
                // Consume once across document and worker lifetimes.
                await storage("remove", key);
                memory.delete(key);
                return { success: true, pending: records.usable(pending, domain) ? pending : null };
            }), sendResponse);
        }
        function clearKey(key) {
            return ordered(key, async () => {
                memory.delete(key);
                await storage("remove", key);
                return { success: true };
            });
        }
        function clear(sender, sendResponse) {
            const key = security.pendingStorageKey(sender);
            if (!key) { sendResponse({ success: false, error: "Invalid tab" }); return; }
            respond(clearKey(key), sendResponse);
        }
        function takeRemembered(sender) {
            const key = security.pendingStorageKey(sender), domain = security.senderOrigin(sender);
            const record = key ? memory.get(key) : null;
            if (key) { memory.delete(key); clearKey(key).catch(() => {}); }
            return records.usable(record, domain) ? record : null;
        }
        async function cleanup() {
            const stored = await storage("get", null);
            await Promise.all(Object.keys(stored || {}).filter(key => key.startsWith(prefix)).map(expire));
        }
        chrome.tabs.onRemoved?.addListener(tabId => { clearKey(`${prefix}${tabId}`).catch(() => {}); });
        return { set, consume, clear, takeRemembered, cleanup };
    }
};
if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundPending;
