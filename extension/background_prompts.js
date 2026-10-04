// Own state per worker instance; browser services are supplied by background.js.
const PasswordManagerBackgroundPrompts = {
    create({ chrome, security, promptState, pendingCredentials, nativeRequest, refreshStatus, crypto, setTimeout }) {
        const pendingCredentialPrompts = new Map();
        const credentialPromptWindows = new Map();
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
                { frameId: pending.frameId },
                () => void chrome.runtime.lastError
            );
        }

        function discardCredentialPrompt(token, action = "cancel", closeWindow = true) {
            const pending = pendingCredentialPrompts.get(token);
            if (!pending) return;
            pendingCredentialPrompts.delete(token);
            notifyCredentialPrompt(token, pending, action);
            if (!Number.isInteger(pending.windowId)) return;
            credentialPromptWindows.delete(pending.windowId);
            if (closeWindow) {
                chrome.windows.remove(pending.windowId, () => void chrome.runtime.lastError);
            }
        }

        function invalidateCredentialPrompts() {
            for (const [token, pending] of pendingCredentialPrompts) {
                if (!pending.completing) discardCredentialPrompt(token, "skipped");
            }
        }

        async function openCredentialPrompt(request, sender) {
            const domain = security.senderOrigin(sender);
            const tabId = sender?.tab?.id;
            const frameId = sender?.frameId;
            let username = request?.username;
            const password = request?.password;
            const remembered = pendingCredentials.takeRemembered(sender);
            if (!username && remembered?.domain === domain && Date.now() - remembered.time < 60_000) {
                username = remembered.username;
            }
            if (!domain || !Number.isInteger(tabId) || !Number.isInteger(frameId)
                || typeof username !== "string" || username.length > 4096
                || typeof password !== "string" || !password || password.length > 64 * 1024
                || /[\0\r\n]/.test(username) || /[\0\r\n]/.test(password)) {
                throw new Error("Invalid credential prompt request");
            }

            // The background owns this request across page navigation. Only open an
            // automatic prompt after an authenticated lookup confirms that the vault
            // is available, including the expected NotFound result for a new site.
            let accounts;
            try {
                accounts = promptState.accountsFromLookup(
                    await nativeRequest("getLoginItems", { domain })
                );
            } catch (_) {
                return { success: true, skipped: true };
            }
            // Account summaries contain no stored passwords. Opening and completing
            // this prompt never disclose whether the submitted password was a match.
            const token = crypto.randomUUID();
            const pending = {
                tabId,
                frameId,
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
                        reject(new Error(error || "Could not open credential prompt"));
                        return;
                    }
                    pending.windowId = window.id;
                    credentialPromptWindows.set(window.id, token);
                    setTimeout(() => discardCredentialPrompt(token), 2 * 60_000);
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
            if (pending.loading) throw new Error("Credential prompt is still loading");
            if (pending.error) throw new Error(pending.error);
            if (pending.completing) throw new Error("Credential operation is already in progress");
            const operation = promptState.operation(pending, request.selection);
            if (operation.action === "cancel") {
                discardCredentialPrompt(request.token, "cancel", false);
                return { success: true };
            }

            const nativeAction = operation.action === "update" ? "updateCredentials" : "saveCredentials";
            pending.completing = true;
            let response;
            try {
                response = await nativeRequest(nativeAction, operation.fields);
                if (!response.success) throw new Error(response.error || "Could not save credentials");
            } catch (error) {
                pending.completing = false;
                throw error;
            }
            discardCredentialPrompt(request.token, operation.action, false);
            refreshStatus();
            return { success: true };
        }

        function data(request, sender) {
            if (!credentialPromptSenderAllowed(sender)) return { success: false, error: "Invalid credential prompt sender" };
            const pending = pendingCredentialPrompts.get(request.token);
            return pending && pending.expiresAt > Date.now()
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

        return { open: openCredentialPrompt, complete: completeCredentialPrompt, invalidate: invalidateCredentialPrompts, data, windowRemoved };
    }
};

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundPrompts;
