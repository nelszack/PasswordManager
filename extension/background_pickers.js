// Own state per worker instance; browser services are supplied by background.js.
const PasswordManagerBackgroundPickers = {
    create({ chrome, security, protocol, nativeRequest, crypto, setTimeout }) {
        const pendingPickers = new Map();
        const pickerWindows = new Map();
        function parseNativeItems(response) {
            return protocol.parseItems(response);
        }

        function pickerSenderAllowed(sender) {
            return security.securePickerSender(
                sender,
                chrome.runtime.id,
                chrome.runtime.getURL("picker.html")
            );
        }

        async function loadSecurePickerItems(kind, domain) {
            let items;
            if (kind === "login" || kind === "totp") {
                items = parseNativeItems(await nativeRequest("getLoginItems", { domain }));
                if (kind === "totp") items = items.filter(item => item?.has_totp === true);
            } else {
                items = parseNativeItems(await nativeRequest("getAutofillItems"));
                items = items.filter(item => item?.kind === kind);
            }
            const summaries = items.map(item => ({
                id: item.id,
                name: String(item.name || ""),
                username: String(item.username || ""),
                kind
            })).filter(item => Number.isSafeInteger(item.id) && item.id > 0);
            return { items: summaries, summaries };
        }

        function invalidateSecurePickers() {
            pendingPickers.clear();
            for (const windowId of pickerWindows.keys()) {
                chrome.windows.remove(windowId, () => void chrome.runtime.lastError);
            }
            pickerWindows.clear();
        }

        async function openSecurePicker(request, sender) {
            const domain = security.senderOrigin(sender);
            const tabId = sender?.tab?.id;
            const frameId = sender?.frameId;
            const kind = request?.kind;
            const documentId = sender?.documentId;
            if (!domain || !Number.isInteger(tabId) || !Number.isInteger(frameId)
                || typeof documentId !== "string" || !documentId
                || !["login", "totp", "payment-card", "identity"].includes(kind)) {
                throw new Error("Invalid secure picker request");
            }
            const tab = await chrome.tabs.get(tabId);
            const topOrigin = security.senderOrigin({ url: tab.url });
            if (!topOrigin) throw new Error("Invalid top-level page origin");

            const token = crypto.randomUUID();
            pendingPickers.set(token, {
                tabId, frameId, documentId, kind, domain, topOrigin,
                crossOrigin: domain !== topOrigin,
                items: [],
                summaries: [],
                loading: true,
                error: null,
                expiresAt: Date.now() + 60_000
            });

            return new Promise((resolve, reject) => {
                chrome.windows.create({
                    url: chrome.runtime.getURL(`picker.html?token=${encodeURIComponent(token)}`),
                    type: "popup",
                    width: 380,
                    height: 480,
                    focused: true
                }, window => {
                    const error = chrome.runtime.lastError?.message;
                    if (error || !window?.id) {
                        pendingPickers.delete(token);
                        reject(new Error(error || "Could not open secure picker"));
                        return;
                    }
                    pickerWindows.set(window.id, token);
                    loadSecurePickerItems(kind, domain)
                        .then(({ items, summaries }) => {
                            const pending = pendingPickers.get(token);
                            if (!pending) return;
                            pending.items = items;
                            pending.summaries = summaries;
                            pending.loading = false;
                        })
                        .catch(loadError => {
                            const pending = pendingPickers.get(token);
                            if (!pending) return;
                            pending.loading = false;
                            pending.error = loadError.message || "Vault items unavailable";
                        });
                    setTimeout(() => {
                        if (!pendingPickers.has(token)) return;
                        pendingPickers.delete(token);
                        chrome.windows.remove(window.id, () => void chrome.runtime.lastError);
                    }, 60_000);
                    resolve({ success: true, token });
                });
            });
        }

        async function completeSecurePicker(request, sender) {
            if (!pickerSenderAllowed(sender)) throw new Error("Invalid picker sender");
            const pending = pendingPickers.get(request?.token);
            if (!pending || pending.expiresAt <= Date.now()) {
                pendingPickers.delete(request?.token);
                throw new Error("Secure picker expired");
            }
            if (request.cancel === true) {
                pendingPickers.delete(request.token);
                return { success: true };
            }
            if (pending.loading) throw new Error("Secure picker is still loading");
            if (pending.error) throw new Error(pending.error);
            if (pending.completing) throw new Error("Selection is already in progress");
            if (pending.crossOrigin && request.confirmCrossOrigin !== true) {
                throw new Error("Confirm filling the embedded site's origin");
            }
            if (!Number.isSafeInteger(request.id) || request.id <= 0) {
                throw new Error("Invalid picker selection");
            }
            const selected = pending.items.find(item => item?.id === request.id);
            if (!selected) throw new Error("Picker selection is unavailable");

            pending.completing = true;
            // Lock/disconnect invalidation also cancels selections awaiting native I/O.
            let payload;
            try {
                if (pending.kind === "login") {
                    const response = await nativeRequest("getLoginItem", {
                        domain: pending.domain, entryId: selected.id
                    });
                    if (!response.success) throw new Error(response.error || "Login unavailable");
                    payload = JSON.parse(response.data);
                } else if (pending.kind === "totp") {
                    const response = await nativeRequest("getTotp", { entryId: selected.id });
                    if (!response.success) throw new Error(response.error || "TOTP unavailable");
                    payload = response.data;
                } else {
                    const response = await nativeRequest("getAutofillItem", { entryId: selected.id });
                    if (!response.success) throw new Error(response.error || "Autofill item unavailable");
                    payload = JSON.parse(response.data);
                }
                if (pendingPickers.get(request.token) !== pending || pending.expiresAt <= Date.now()) {
                    throw new Error("Secure picker expired");
                }
                pendingPickers.delete(request.token);
                await chrome.tabs.sendMessage(
                    pending.tabId,
                    { action: "securePickerResult", token: request.token, payload },
                    { documentId: pending.documentId }
                );
                return { success: true };
            } finally {
                pending.completing = false;
            }
        }

        function data(request, sender) {
            if (!pickerSenderAllowed(sender)) return { success: false, error: "Invalid picker sender" };
            const pending = pendingPickers.get(request.token);
            return pending && pending.expiresAt > Date.now()
                ? { success: true, kind: pending.kind, origin: pending.domain, topOrigin: pending.topOrigin,
                    crossOrigin: pending.crossOrigin, items: pending.summaries, loading: pending.loading, error: pending.error }
                : { success: false, error: "Secure picker expired" };
        }
        function windowRemoved(windowId) {
            const token = pickerWindows.get(windowId);
            if (!token) return;
            pickerWindows.delete(windowId);
            pendingPickers.delete(token);
        }

        return { open: openSecurePicker, complete: completeSecurePicker, invalidate: invalidateSecurePickers, data, windowRemoved };
    }
};

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundPickers;
