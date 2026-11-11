// Own state per worker instance; browser services are supplied by background.js.
const PasswordManagerBackgroundPrompts = {
    create({ chrome, security, promptState, pendingCredentials, matchesFilledLogin, nativeRequest, reconcile, refreshStatus, crypto, setTimeout, onLoginContext }) {
        const pendingCredentialPrompts = new Map();
        const credentialPromptWindows = new Map();
        let generation = 0;
        function credentialPromptSenderAllowed(sender) {
            return security.securePickerSender(
                sender,
                chrome.runtime.id,
                chrome.runtime.getURL("credential_prompt.html")
            );
        }

        function notifyCredentialPrompt(token, pending, action) {
            chrome.tabs.sendMessage(
                pending.tabId,
                { action: "credentialPromptResult", token, result: { action } },
                { documentId: pending.documentId },
                () => void chrome.runtime.lastError
            );
        }

        function discardCredentialPrompt(token, action = "cancel", closeWindow = true) {
            const pending = pendingCredentialPrompts.get(token);
            if (!pending) return;
            pendingCredentialPrompts.delete(token);
            pending.state = { phase: "closed" };
            notifyCredentialPrompt(token, pending, action);
            if (!Number.isInteger(pending.windowId)) return;
            credentialPromptWindows.delete(pending.windowId);
            if (closeWindow) {
                chrome.windows.remove(pending.windowId, () => void chrome.runtime.lastError);
            }
        }

        function invalidateCredentialPrompts() {
            generation++;
            for (const [token, pending] of pendingCredentialPrompts) {
                if (pending.state.phase === "reviewingOutcome") continue;
                if (pending.state.phase === "saving") pending.state = { phase: "invalidatedSaving" };
                else if (pending.state.phase !== "invalidatedSaving") discardCredentialPrompt(token, "skipped");
            }
        }

        async function openCredentialPrompt(request, sender) {
            const epoch = generation;
            const domain = security.senderOrigin(sender);
            const tabId = sender?.tab?.id;
            const frameId = sender?.frameId;
            const documentId = sender?.documentId;
            let username = request?.username;
            const password = request?.password;
            if (!domain || !Number.isInteger(tabId) || !Number.isInteger(frameId)
                || typeof documentId !== "string" || !documentId
                || typeof username !== "string" || username.length > 4096
                || typeof password !== "string" || !password || password.length > 64 * 1024
                || /[\0\r\n]/.test(username) || /[\0\r\n]/.test(password)) {
                throw new Error("Invalid credential prompt request");
            }
            const remembered = await pendingCredentials.takeRemembered(sender);
            if (epoch !== generation) return { success: true, skipped: true };
            if (!username && remembered?.domain === domain && Date.now() - remembered.time < 60_000) {
                username = remembered.username;
            }

            // The background owns this request across page navigation. Only open an
            // automatic prompt after an authenticated lookup confirms that the vault
            // is available, including the expected NotFound result for a new site.
            let accounts, sessionId;
            try {
                const response = await nativeRequest("getLoginItems", { domain });
                accounts = promptState.accountsFromLookup(response);
                sessionId = response.sessionId;
                if (typeof sessionId !== "string" || !/^[a-fA-F0-9]{64}$/.test(sessionId)) return { success: true, skipped: true };
            } catch (_) {
                return { success: true, skipped: true };
            }
            if (epoch !== generation) return { success: true, skipped: true };
            // Compare only with a login explicitly released to this tab/frame/origin.
            // Never fetch unselected secrets to test passwords supplied by a page.
            const matched = await matchesFilledLogin(sender, username, password);
            if (epoch !== generation) return { success: true, skipped: true };
            onLoginContext?.({ sender, accounts: (username ? accounts.filter(account => account.username === username) : accounts).map(account => ({ ...account, sessionId })) });
            if (matched) {
                return { success: true, skipped: true };
            }
            const token = crypto.randomUUID();
            const pending = {
                tabId,
                frameId,
                documentId,
                sessionId,
                domain,
                username,
                state: { phase: "ready", password },
                data: promptState.describe(accounts, username, domain),
                expiresAt: Date.now() + 2 * 60_000,
                windowId: null
            };
            pendingCredentialPrompts.set(token, pending);

            return new Promise((resolve, reject) => {
                chrome.windows.create({
                    url: chrome.runtime.getURL(
                        `credential_prompt.html?token=${encodeURIComponent(token)}`
                    ),
                    type: "popup",
                    width: 400,
                    height: 430,
                    focused: true
                }, window => {
                    const error = chrome.runtime.lastError?.message;
                    if (error || !window?.id) {
                        pendingCredentialPrompts.delete(token);
                        pending.state = { phase: "closed" };
                        reject(new Error(error || "Could not open credential prompt"));
                        return;
                    }
                    if (pendingCredentialPrompts.get(token) !== pending || pending.expiresAt <= Date.now()) {
                        discardCredentialPrompt(token, "skipped");
                        chrome.windows.remove(window.id, () => void chrome.runtime.lastError);
                        resolve({ success: true, skipped: true });
                        return;
                    }
                    pending.windowId = window.id;
                    credentialPromptWindows.set(window.id, token);
                    setTimeout(() => discardCredentialPrompt(token), Math.max(0, pending.expiresAt - Date.now()));
                    resolve({ success: true, token });
                });
            });
        }

        async function completeCredentialPrompt(request, sender) {
            if (!credentialPromptSenderAllowed(sender)) throw new Error("Invalid credential prompt sender");
            const pending = pendingCredentialPrompts.get(request?.token);
            if (!pending || pending.expiresAt <= Date.now()) {
                discardCredentialPrompt(request?.token);
                throw new Error("Credential prompt expired");
            }
            if (["saving", "invalidatedSaving"].includes(pending.state.phase)) throw new Error("Credential operation is already in progress");
            if (request.selection?.action === "cancel") {
                discardCredentialPrompt(request.token, "cancel", false);
                return { success: true };
            }
            if (pending.state.phase === "reviewingOutcome") throw new Error(pending.state.error);
            const operation = promptState.operation({ ...pending, password: pending.state.password }, request.selection);

            const nativeAction = operation.action === "update" ? "updateCredentials" : "saveCredentials";
            pending.state = { phase: "saving", password: pending.state.password };
            let response;
            try {
                response = await nativeRequest(nativeAction, operation.fields);
                if (!response.success) {
                    const error = new Error(response.error || "Could not save credentials");
                    error.uncertain = Boolean(response.uncertain);
                    error.operationId = response.operationId;
                    throw error;
                }
            } catch (error) {
                if (error.uncertain && pending.windowId !== null) {
                    // An accepted operation is now an outcome review, not a secret
                    // decision. It can survive transport recovery without its password.
                    pending.state = { phase: "reviewingOutcome", operationId: error.operationId,
                        operationAction: operation.action, error: error.message };
                } else if (pending.state.phase !== "saving" || pending.windowId === null) {
                    discardCredentialPrompt(request.token, "skipped");
                } else {
                    pending.state = { phase: "ready", password: pending.state.password };
                }
                throw error;
            }
            discardCredentialPrompt(request.token, operation.action, false);
            refreshStatus();
            return { success: true };
        }

        async function review(request, sender) {
            if (!credentialPromptSenderAllowed(sender)) throw new Error("Invalid credential prompt sender");
            const pending = pendingCredentialPrompts.get(request?.token);
            if (!pending || pending.state.phase !== "reviewingOutcome") throw new Error("Credential operation is unavailable");
            const response = await reconcile(pending.state.operationId);
            if (!response.success) return response;
            const state = response.data.state;
            if (["committed", "committed_durability_unknown", "failed"].includes(state)) {
                discardCredentialPrompt(request.token, state === "failed" ? "skipped" : pending.state.operationAction, false);
                refreshStatus();
            }
            return response;
        }

        function data(request, sender) {
            if (!credentialPromptSenderAllowed(sender)) return { success: false, error: "Invalid credential prompt sender" };
            const pending = pendingCredentialPrompts.get(request.token);
            return pending && !["invalidatedSaving", "closed"].includes(pending.state.phase) && pending.expiresAt > Date.now()
                ? { success: true, data: pending.data, loading: false, error: pending.state.error || null }
                : { success: false, error: "Credential prompt expired" };
        }
        function windowRemoved(windowId) {
            const token = credentialPromptWindows.get(windowId);
            if (!token) return false;
            credentialPromptWindows.delete(windowId);
            const pending = pendingCredentialPrompts.get(token);
            if (pending && ["saving", "invalidatedSaving"].includes(pending.state.phase)) pending.windowId = null;
            else discardCredentialPrompt(token, "cancel", false);
            return true;
        }

        return { review, open: openCredentialPrompt, complete: completeCredentialPrompt, invalidate: invalidateCredentialPrompts, data, windowRemoved };
    }
};

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundPrompts;
