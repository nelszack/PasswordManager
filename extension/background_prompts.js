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
            pending.password = "";
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
                pending.password = "";
                if (pending.operationId) continue;
                pending.invalidated = true;
                if (!pending.completing) discardCredentialPrompt(token, "skipped");
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
                password,
                data: promptState.describe(accounts, username, domain),
                loading: false,
                error: null,
                expiresAt: Date.now() + 2 * 60_000,
                windowId: null,
                completing: false
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
                        pending.password = "";
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
            if (pending.completing) throw new Error("Credential operation is already in progress");
            if (request.selection?.action === "cancel") {
                discardCredentialPrompt(request.token, "cancel", false);
                return { success: true };
            }
            if (pending.loading) throw new Error("Credential prompt is still loading");
            if (pending.error) throw new Error(pending.error);
            const operation = promptState.operation(pending, request.selection);

            const nativeAction = operation.action === "update" ? "updateCredentials" : "saveCredentials";
            pending.completing = true;
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
                pending.completing = false;
                if (error.uncertain && pending.windowId !== null) {
                    // An accepted operation is now an outcome review, not a secret
                    // decision. It can survive transport recovery without its password.
                    pending.operationId = error.operationId; pending.operationAction = operation.action;
                    pending.error = error.message; pending.password = ""; pending.invalidated = false;
                } else if (pending.invalidated || pending.windowId === null) {
                    discardCredentialPrompt(request.token, "skipped");
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
            if (!pending || !pending.operationId) throw new Error("Credential operation is unavailable");
            const response = await reconcile(pending.operationId);
            if (!response.success) return response;
            const state = response.data.state;
            if (["committed", "committed_durability_unknown", "failed"].includes(state)) {
                discardCredentialPrompt(request.token, state === "failed" ? "skipped" : pending.operationAction, false);
                refreshStatus();
            }
            return response;
        }

        function data(request, sender) {
            if (!credentialPromptSenderAllowed(sender)) return { success: false, error: "Invalid credential prompt sender" };
            const pending = pendingCredentialPrompts.get(request.token);
            return pending && !pending.invalidated && pending.expiresAt > Date.now()
                ? { success: true, data: pending.data, loading: pending.loading, error: pending.error }
                : { success: false, error: "Credential prompt expired" };
        }
        function windowRemoved(windowId) {
            const token = credentialPromptWindows.get(windowId);
            if (!token) return false;
            credentialPromptWindows.delete(windowId);
            const pending = pendingCredentialPrompts.get(token);
            if (pending?.completing) pending.windowId = null;
            else discardCredentialPrompt(token, "cancel", false);
            return true;
        }

        return { review, open: openCredentialPrompt, complete: completeCredentialPrompt, invalidate: invalidateCredentialPrompts, data, windowRemoved };
    }
};

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundPrompts;
