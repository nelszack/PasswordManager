// Own state per worker instance; browser services are supplied by background.js.
const PasswordManagerBackgroundRouter = {
    create({ chrome, security, relay, nativeRequest, refreshStatus, pickers, prompts, pendingCredentials }) {
        const pendingRelays = new Map();
        function sendAction(action, fields, sendResponse, refreshAfter = false) {
            nativeRequest(action, fields)
                .then(response => {
                    sendResponse(response.success
                        ? { success: true, data: response.data }
                        : { success: false, error: response.error });
                    if (refreshAfter) refreshStatus();
                })
                .catch(error => {
                    sendResponse({ success: false, error: error.message });
                    if (refreshAfter) refreshStatus();
                });
        }

        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            if (request.action === "openCredentialPrompt") {
                prompts.open(request, sender)
                    .then(sendResponse)
                    .catch(error => sendResponse({ success: false, error: error.message }));
                return true;
            }
            if (request.action === "getCredentialPromptData") {
                sendResponse(prompts.data(request, sender));
                return true;
            }
            if (request.action === "completeCredentialPrompt") {
                prompts.complete(request, sender)
                    .then(sendResponse)
                    .catch(error => sendResponse({ success: false, error: error.message }));
                return true;
            }
            if (request.action === "openSecurePicker") {
                pickers.open(request, sender)
                    .then(sendResponse)
                    .catch(error => sendResponse({ success: false, error: error.message }));
                return true;
            }
            if (request.action === "getSecurePickerData") {
                sendResponse(pickers.data(request, sender));
                return true;
            }
            if (request.action === "completeSecurePicker") {
                pickers.complete(request, sender)
                    .then(sendResponse)
                    .catch(error => sendResponse({ success: false, error: error.message }));
                return true;
            }
            if (request.action === "getStatus") {
                refreshStatus()
                    .then(sendResponse)
                    .catch(error => sendResponse({
                        native: false,
                        running: false,
                        locked: false,
                        error: error.message
                    }));
                return true;
            }
            if (request.action === "getCredentials") {
                const domain = security.senderOrigin(sender);
                if (!domain) sendResponse({ success: false, error: "Invalid page origin" });
                else sendAction("getLoginItems", { domain }, sendResponse);
                return true;
            }
            if (request.action === "saveCredentials") {
                const domain = security.senderOrigin(sender);
                if (!domain) sendResponse({ success: false, error: "Invalid page origin" });
                else sendAction("saveCredentials", {
                    domain,
                    username: request.username,
                    password: request.password,
                    name: request.name
                }, sendResponse, true);
                return true;
            }
            if (request.action === "updateCredentials") {
                const domain = security.senderOrigin(sender);
                if (!domain) sendResponse({ success: false, error: "Invalid page origin" });
                else sendAction("updateCredentials", {
                    domain,
                    username: request.username,
                    password: request.password,
                    name: request.name,
                    entryId: request.id
                }, sendResponse, true);
                return true;
            }
            if (request.action === "getRelayedCredentials") {
                const authorizedRelay = relay.authorizeCredentialRequest(
                    request, sender, pendingRelays
                );
                if (!authorizedRelay) sendResponse({ success: false, error: "Invalid credential relay" });
                else sendAction("getLoginItems", { domain: authorizedRelay.domain }, sendResponse);
                return true;
            }
            if (request.action === "saveRelayedCredentials"
                || request.action === "updateRelayedCredentials") {
                const authorizedRelay = relay.authorizeCredentialRequest(
                    request, sender, pendingRelays, true
                );
                if (!authorizedRelay) {
                    sendResponse({ success: false, error: "Invalid credential relay" });
                } else {
                    const update = request.action === "updateRelayedCredentials";
                    sendAction(update ? "updateCredentials" : "saveCredentials", {
                        domain: authorizedRelay.domain,
                        username: request.username,
                        password: request.password,
                        name: request.name,
                        ...(update ? { entryId: request.id } : {})
                    }, sendResponse, true);
                }
                return true;
            }
            if (request.action === "setPendingCredentials") {
                pendingCredentials.set(request, sender, sendResponse);
                return true;
            }
            if (request.action === "consumePendingCredentials") {
                pendingCredentials.consume(sender, sendResponse);
                return true;
            }
            if (request.action === "clearPendingCredentials") {
                pendingCredentials.clear(sender, sendResponse);
                return true;
            }
            if (request.action === "lockVault") {
                pickers.invalidate();
                sendAction("lock", {}, sendResponse, true);
                return true;
            }
            if (request.action === "relayToParent") {
                const route = relay.requestRoute(request.data, sender);
                if (route) {
                    pendingRelays.set(
                        relay.relayKey(route.tabId, request.data.token),
                        {
                            sourceFrameId: sender.frameId,
                            domain: request.data.domain,
                            expiresAt: Date.now() + 5 * 60_000
                        }
                    );
                    chrome.tabs.sendMessage(
                        route.tabId,
                        route.message,
                        { frameId: route.frameId },
                        () => void chrome.runtime.lastError
                    );
                    sendResponse({ ok: true });
                } else {
                    sendResponse({ ok: false });
                }
                return false;
            }
            if (request.action === "relayLoginResult") {
                const route = relay.resultRoute(request, sender);
                if (route) {
                    chrome.tabs.sendMessage(
                        route.tabId,
                        route.message,
                        { frameId: route.frameId },
                        () => void chrome.runtime.lastError
                    );
                    sendResponse({ ok: true });
                } else {
                    sendResponse({ ok: false });
                }
                return false;
            }
        });

        return { cleanupExpired: () => relay.cleanupExpired(pendingRelays) };
    }
};

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundRouter;
