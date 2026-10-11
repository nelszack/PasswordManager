const PasswordManagerBackgroundDuo = {
    create({ chrome, security, protocol, detection, nativeRequest, refreshStatus, crypto, setTimeout }) {
        const sessions = new Map(), tokens = new Map(), windows = new Map(), recentLogins = new Map(), observers = new Map();
        let generation = 0;
        const lifetime = 5 * 60_000;
        const keyFor = sender => JSON.stringify([sender.tab.id, sender.frameId, sender.documentId]);
        const requestKey = r => JSON.stringify([r.entryId, r.id, r.fingerprint]);
        const trusted = sender => security.securePickerSender(sender, chrome.runtime.id, chrome.runtime.getURL("duo_prompt.html"));

        function rememberLogin({ sender, accounts }) {
            const items = accounts.filter(item => item.has_duo === true && Number.isSafeInteger(item.id) && item.id > 0)
                .map(({ id, name }) => ({ id, name: String(name || "") }));
            if (!items.length || !Number.isInteger(sender?.tab?.id)) return;
            const record = { origin: security.senderOrigin(sender), items, expiresAt: Date.now() + lifetime };
            recentLogins.set(sender.tab.id, record);
            setTimeout(() => { if (recentLogins.get(sender.tab.id) === record) recentLogins.delete(sender.tab.id); }, lifetime);
        }
        function dismiss(session) {
            for (const r of session.requests) session.dismissed.add(requestKey(r));
            if (session.token) tokens.delete(session.token);
            session.token = null;
            if (Number.isInteger(session.windowId)) {
                windows.delete(session.windowId);
                chrome.windows.remove(session.windowId, () => void chrome.runtime.lastError);
            }
            session.windowId = null;
        }
        function discard(session) {
            dismiss(session);
            if (sessions.get(session.key) === session) sessions.delete(session.key);
        }
        function invalidate() {
            generation++;
            for (const session of sessions.values()) dismiss(session);
            sessions.clear(); recentLogins.clear(); tokens.clear();
        }
        async function current(session) {
            if (sessions.get(session.key) !== session || session.expiresAt <= Date.now()) return false;
            try {
                const tab = await chrome.tabs.get(session.tabId);
                const state = await chrome.tabs.sendMessage(session.tabId, { action: "getDuoChallengeState" }, { documentId: session.documentId });
                return sessions.get(session.key) === session && session.expiresAt > Date.now()
                    && security.senderOrigin({ url: tab.url }) === session.topOrigin && state?.active === true;
            } catch (_) { return false; }
        }
        async function lookup(origin) {
            const response = await nativeRequest("getLoginItems", { domain: origin });
            if (!response.success && /not found/i.test(response.error)) return [];
            return protocol.parseItems(response).filter(item => item.has_duo === true && Number.isSafeInteger(item.id) && item.id > 0)
                .map(({ id, name }) => ({ id, name: String(name || "") }));
        }
        async function poll(session) {
            if (session.failure) throw new Error(session.failure);
            if (session.polling) return session.polling;
            session.polling = (async () => {
                if (!await current(session)) { discard(session); throw new Error("Duo login page is no longer active"); }
                const requests = [];
                for (const item of session.items) {
                    const response = await nativeRequest("managerDuoRequests", { entryId: item.id });
                    if (!response.success) throw new Error(response.error || "Duo requests unavailable");
                    if (!Array.isArray(response.data)) throw new Error("Invalid Duo request response");
                    for (const r of response.data) {
                        if (r.expires_at * 1000 > Date.now()) requests.push({ ...r, entryId: item.id, entryName: item.name });
                    }
                }
                if (!await current(session)) { discard(session); throw new Error("Duo login page is no longer active"); }
                session.requests = requests;
                const pending = new Set(requests.map(requestKey));
                for (const key of session.dismissed) if (!pending.has(key)) session.dismissed.delete(key);
                return requests;
            })().finally(() => { session.polling = null; });
            return session.polling;
        }
        async function beginObserve(_request, sender) {
            const origin = security.senderOrigin(sender);
            if (!origin || !Number.isInteger(sender?.tab?.id) || !Number.isInteger(sender?.frameId)
                || typeof sender.documentId !== "string" || !sender.documentId) throw new Error("Invalid Duo page request");
            const epoch = generation;
            const status = await refreshStatus();
            if (epoch !== generation || !status.native || !status.running || status.locked) return { success: true };
            const key = keyFor(sender);
            for (const other of sessions.values()) {
                if (other.tabId === sender.tab.id && other.frameId === sender.frameId && other.documentId !== sender.documentId) discard(other);
            }
            let session = sessions.get(key);
            if (!session) {
                // Reserve before I/O so repeated content messages cannot open duplicates.
                if (sessions.size >= 64) return { success: true };
                const tab = await chrome.tabs.get(sender.tab.id);
                const topOrigin = security.senderOrigin({ url: tab.url });
                if (!topOrigin) throw new Error("Invalid top-level login page");
                session = { key, tabId: sender.tab.id, frameId: sender.frameId, documentId: sender.documentId, origin, topOrigin,
                    sourceOrigin: topOrigin, items: [], requests: [], dismissed: new Set(), token: null,
                    windowId: null, expiresAt: Date.now() + lifetime };
                sessions.set(key, session);
                setTimeout(() => { if (sessions.get(key) === session) discard(session); }, lifetime);
                session.loading = (async () => {
                    if (!await current(session)) throw new Error("Duo login page is no longer active");
                    session.items = await lookup(topOrigin);
                    if (!session.items.length && origin !== topOrigin) session.items = await lookup(origin);
                    const recent = recentLogins.get(sender.tab.id);
                    if (!session.items.length && detection.duoOrigin(origin) && recent?.expiresAt > Date.now()) {
                        session.items = recent.items; session.sourceOrigin = recent.origin;
                    }
                })();
            }
            try {
                await session.loading;
                if (session.failure) return { success: true };
                if (!await current(session)) { discard(session); return { success: true }; }
                if (!session.items.length) { discard(session); return { success: true }; }
                const requests = await poll(session);
                if (!session.token && requests.some(r => !session.dismissed.has(requestKey(r)))) {
                    const token = crypto.randomUUID();
                    session.token = token; tokens.set(token, session);
                    await new Promise((resolve, reject) => chrome.windows.create({
                        url: chrome.runtime.getURL(`duo_prompt.html?token=${encodeURIComponent(token)}`),
                        type: "popup", width: 440, height: 590, focused: true
                    }, window => {
                        const error = chrome.runtime.lastError?.message;
                        if (error || !Number.isInteger(window?.id)) { dismiss(session); reject(new Error(error || "Could not open Duo window")); return; }
                        if (tokens.get(token) !== session) { chrome.windows.remove(window.id, () => void chrome.runtime.lastError); resolve(); return; }
                        session.windowId = window.id; windows.set(window.id, session); resolve();
                    }));
                }
                // Never expose tokens, account names, requests or fingerprints to a page.
                return { success: true };
            } catch (error) { discard(session); throw error; }
        }
        function observe(request, sender) {
            if (!Number.isInteger(sender?.tab?.id) || !Number.isInteger(sender?.frameId) || typeof sender.documentId !== "string") {
                return Promise.reject(new Error("Invalid Duo page request"));
            }
            const key = keyFor(sender);
            if (observers.has(key)) return observers.get(key);
            const work = beginObserve(request, sender).finally(() => { if (observers.get(key) === work) observers.delete(key); });
            observers.set(key, work); return work;
        }
        function authorize(request, sender) {
            if (!trusted(sender)) throw new Error("Invalid Duo window sender");
            const session = tokens.get(request.token);
            if (!session || session.expiresAt <= Date.now()) throw new Error("Duo window expired");
            return session;
        }
        async function data(request, sender) {
            const session = authorize(request, sender);
            if (!session.completing) await poll(session);
            if (tokens.get(request.token) !== session) throw new Error("Duo window expired");
            return { success: true, origin: session.origin, topOrigin: session.topOrigin,
                sourceOrigin: session.sourceOrigin, requests: session.requests };
        }
        async function complete(request, sender) {
            const session = authorize(request, sender);
            if (session.completing) throw new Error("Duo decision is already in progress");
            if (request.cancel === true) { dismiss(session); return { success: true }; }
            if (session.failure) throw new Error(session.failure);
            const r = session.requests.find(r => r.entryId === request.entryId && r.id === request.requestId && r.fingerprint === request.fingerprint);
            if (!r || r.expires_at * 1000 <= Date.now()) throw new Error("Duo request changed or expired; review it again");
            if (typeof request.approve !== "boolean") throw new Error("Choose approve or deny");
            if (request.approve && r.unsupported) throw new Error(r.unsupported);
            const code = request.approve ? request.verificationCode || "" : "";
            if (typeof code !== "string" || (request.approve && r.code_digits && !new RegExp(`^[0-9]{${r.code_digits}}$`).test(code))
                || (!r.code_digits && code !== "")) throw new Error("Enter the verification code shown on the login page");
            session.completing = true;
            try {
                if (!await current(session) || tokens.get(request.token) !== session) {
                    discard(session); throw new Error("Duo login page is no longer active");
                }
                const response = await nativeRequest("managerDuoRespond", { entryId: r.entryId, requestId: r.id,
                    fingerprint: r.fingerprint, approve: request.approve, verificationCode: code });
                if (!response.success) throw new Error(response.error || "Duo decision failed");
                session.dismissed.add(requestKey(r));
                session.requests = session.requests.filter(other => requestKey(other) !== requestKey(r));
                if (!session.requests.length) dismiss(session);
                return { success: true, remaining: session.requests.length };
            } catch (error) {
                // A timeout may have answered the request. Show the error, remove
                // decision controls, and require a new page/review before retrying.
                if (tokens.get(request.token) === session) {
                    session.failure = `${error.message || "Duo decision failed"}. Check the login before retrying.`;
                    session.requests = [];
                    throw new Error(session.failure);
                }
                throw error;
            } finally { session.completing = false; }
        }
        function windowRemoved(windowId) {
            const session = windows.get(windowId);
            if (!session) return false;
            windows.delete(windowId); session.windowId = null; dismiss(session); return true;
        }
        return { observe, data, complete, rememberLogin, invalidate, windowRemoved };
    }
};
if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundDuo;
