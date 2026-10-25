// Own state per worker instance; browser services are supplied by background.js.
const PasswordManagerBackgroundPickers = {
    create({ chrome, security, protocol, nativeRequest, crypto, setTimeout, onLoginSelected }) {
        const pendingPickers = new Map();
        const pickerWindows = new Map();
        const filledLogins = new Map();
        const filledLoginLifetime = 10 * 60_000;
        let generation = 0;

        function filledLoginKey({ tabId, frameId, domain }) {
            return JSON.stringify([tabId, frameId, domain]);
        }

        async function loginFingerprint(username, password) {
            const bytes = new TextEncoder().encode(JSON.stringify([username, password]));
            const digest = await crypto.subtle.digest("SHA-256", bytes);
            return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
        }

        async function matchesFilledLogin(sender, username, password) {
            const key = filledLoginKey({
                tabId: sender?.tab?.id, frameId: sender?.frameId,
                domain: security.senderOrigin(sender)
            });
            const record = filledLogins.get(key);
            if (!record || record.expiresAt <= Date.now()) return false;
            // A password-only step can omit the username selected in the picker.
            const fingerprint = await loginFingerprint(username || record.username, password);
            return filledLogins.get(key) === record && record.expiresAt > Date.now()
                && record.fingerprint === fingerprint;
        }

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
            let items, response;
            if (kind === "login" || kind === "totp") {
                response = await nativeRequest("getLoginItems", { domain });
                items = parseNativeItems(response);
                if (kind === "totp") items = items.filter(item => item?.has_totp === true);
            } else {
                response = await nativeRequest("getAutofillItems");
                items = parseNativeItems(response);
                items = items.filter(item => item?.kind === kind);
            }
            const summaries = items.map(item => ({
                id: item.id,
                revision: item.revision,
                name: String(item.name || ""),
                username: String(item.username || ""),
                kind,
                has_duo: item.has_duo === true
            })).filter(item => Number.isSafeInteger(item.id) && item.id > 0);
            return { items: summaries, summaries, sessionId: protocol.sessionId(response) };
        }

        function discardPicker(token, closeWindow = true) {
            const pending = pendingPickers.get(token);
            if (!pending) return;
            pendingPickers.delete(token);
            chrome.tabs.sendMessage(pending.tabId,
                { action: "securePickerResult", token, payload: null },
                { documentId: pending.documentId }).catch(() => {});
            if (!Number.isInteger(pending.windowId)) return;
            pickerWindows.delete(pending.windowId);
            if (closeWindow) chrome.windows.remove(pending.windowId, () => void chrome.runtime.lastError);
        }

        function invalidateSecurePickers() {
            generation++;
            for (const token of pendingPickers.keys()) discardPicker(token);
            filledLogins.clear();
        }

        function requirePendingPicker(token, pending) {
            if (pendingPickers.get(token) !== pending || pending.expiresAt <= Date.now()) {
                discardPicker(token);
                throw new Error("Secure picker expired");
            }
        }

        async function requireCurrentDestination(token, pending) {
            let tab;
            try { tab = await chrome.tabs.get(pending.tabId); }
            catch (_) {
                discardPicker(token);
                throw new Error("Secure picker expired; the destination is unavailable");
            }
            if (pendingPickers.get(token) !== pending || pending.expiresAt <= Date.now()
                || security.senderOrigin({ url: tab.url }) !== pending.topOrigin) {
                discardPicker(token);
                throw new Error("Secure picker expired; the destination changed");
            }
        }

        async function openSecurePicker(request, sender) {
            const epoch = generation;
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
            if (epoch !== generation) throw new Error("Secure picker expired");
            const topOrigin = security.senderOrigin({ url: tab.url });
            if (!topOrigin) throw new Error("Invalid top-level page origin");

            const token = crypto.randomUUID();
            const pending = {
                tabId, frameId, documentId, kind, domain, topOrigin,
                crossOrigin: domain !== topOrigin,
                items: [],
                summaries: [],
                loading: true,
                error: null,
                expiresAt: Date.now() + 60_000,
                windowId: null
            };
            pendingPickers.set(token, pending);

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
                    if (pendingPickers.get(token) !== pending || pending.expiresAt <= Date.now()) {
                        discardPicker(token);
                        chrome.windows.remove(window.id, () => void chrome.runtime.lastError);
                        reject(new Error("Secure picker expired"));
                        return;
                    }
                    pending.windowId = window.id;
                    pickerWindows.set(window.id, token);
                    loadSecurePickerItems(kind, domain)
                        .then(({ items, summaries, sessionId }) => {
                            const pending = pendingPickers.get(token);
                            if (!pending) return;
                            pending.sessionId = sessionId;
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
                    setTimeout(() => discardPicker(token), Math.max(0, pending.expiresAt - Date.now()));
                    resolve({ success: true, token });
                });
            });
        }

        async function completeSecurePicker(request, sender) {
            if (!pickerSenderAllowed(sender)) throw new Error("Invalid picker sender");
            const pending = pendingPickers.get(request?.token);
            if (!pending || pending.expiresAt <= Date.now()) {
                discardPicker(request?.token);
                throw new Error("Secure picker expired");
            }
            if (request.cancel === true) {
                discardPicker(request.token);
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
            const epoch = generation;
            // Lock/disconnect invalidation also cancels selections awaiting native I/O.
            let payload;
            let filledLogin;
            const binding = { expectedSession: pending.sessionId, expectedRevision: selected.revision };
            try {
                await requireCurrentDestination(request.token, pending);
                requirePendingPicker(request.token, pending);
                if (pending.kind === "login") {
                    const response = await nativeRequest("getLoginItem", {
                        domain: pending.domain, entryId: selected.id, ...binding
                    });
                    if (!response.success) throw new Error(response.error || "Login unavailable");
                    payload = response.data;
                    const username = payload.username ? String(payload.username).trim() : "";
                    filledLogin = {
                        username,
                        fingerprint: await loginFingerprint(username, payload.password),
                        expiresAt: Date.now() + filledLoginLifetime
                    };
                } else if (pending.kind === "totp") {
                    const response = await nativeRequest("getTotp", { domain: pending.domain, entryId: selected.id, ...binding });
                    if (!response.success) throw new Error(response.error || "TOTP unavailable");
                    payload = response.data;
                } else {
                    const response = await nativeRequest("getAutofillItem", { entryId: selected.id, ...binding });
                    if (!response.success) throw new Error(response.error || "Autofill item unavailable");
                    payload = response.data;
                }
                // Recheck after native I/O as well: confirmation belongs to the
                // top-level origin shown in the picker, even for an embedded frame.
                await requireCurrentDestination(request.token, pending);
                // Keep this guard in the continuation that releases the secret;
                // cancellation can run between an async check and its caller.
                requirePendingPicker(request.token, pending);
                pendingPickers.delete(request.token);
                pickerWindows.delete(pending.windowId);
                const key = filledLoginKey(pending);
                if (filledLogin) {
                    // Remember only a fingerprint of the explicitly selected secret,
                    // before delivery so an immediate submit can recognize it.
                    filledLogins.set(key, filledLogin);
                    setTimeout(() => {
                        if (filledLogins.get(key) === filledLogin) filledLogins.delete(key);
                    }, filledLoginLifetime);
                }
                try {
                    await chrome.tabs.sendMessage(
                        pending.tabId,
                        { action: "securePickerResult", token: request.token, payload },
                        { documentId: pending.documentId }
                    );
                    if (filledLogin && epoch === generation) onLoginSelected?.({
                        sender: { tab: { id: pending.tabId }, url: pending.domain }, accounts: [{ ...selected, sessionId: pending.sessionId }]
                    });
                } catch (error) {
                    if (filledLogin && filledLogins.get(key) === filledLogin) filledLogins.delete(key);
                    throw error;
                }
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
            discardPicker(token, false);
        }

        return { open: openSecurePicker, complete: completeSecurePicker, invalidate: invalidateSecurePickers, data, windowRemoved, matchesFilledLogin };
    }
};

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundPickers;
