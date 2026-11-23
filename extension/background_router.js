// Own state per worker instance; browser services are supplied by background.js.
const PasswordManagerBackgroundRouter = {
    create({
        chrome,
        security,
        contract,
        nativeRequest,
        reconcile,
        pendingOperations = () => [],
        acknowledgeUnknown,
        startup = Promise.resolve(),
        refreshStatus,
        pickers,
        prompts,
        pendingCredentials,
        duo,
        passkeys,
        popup,
    }) {
        function sendAction(action, fields, sendResponse, refreshAfter = false) {
            nativeRequest(action, fields)
                .then(response => {
                    sendResponse(
                        response.success
                            ? {
                                  success: true,
                                  data: response.data,
                                  operation: response.operation,
                                  sessionId: response.sessionId,
                              }
                            : {
                                  success: false,
                                  error: response.error,
                                  uncertain: Boolean(response.uncertain),
                                  operationId: response.operationId,
                                  operationAction: response.operationAction,
                                  code: response.code,
                              }
                    );
                    if (refreshAfter) refreshStatus();
                })
                .catch(error => {
                    sendResponse(operationFailure(error));
                    if (refreshAfter) refreshStatus();
                });
        }

        function errorResponse(error) {
            return { success: false, error: error.message };
        }
        function operationFailure(error) {
            return {
                success: false,
                error: error.message,
                uncertain: Boolean(error.uncertain),
                operationId: error.operationId,
                operationAction: error.operationAction,
            };
        }
        // Requests answered by one service method. Each method authorizes its own
        // sender; rejections become failure responses.
        const serviceActions = {
            observeDuoChallenge: { handle: (request, sender) => duo.observe(request, sender) },
            getDuoPromptData: { handle: (request, sender) => duo.data(request, sender) },
            completeDuoPrompt: { handle: (request, sender) => duo.complete(request, sender) },
            openCredentialPrompt: { handle: (request, sender) => prompts.open(request, sender) },
            reviewCredentialPrompt: { handle: (request, sender) => prompts.review(request, sender) },
            getCredentialPromptData: { handle: (request, sender) => prompts.data(request, sender) },
            revealCredentialPassword: { handle: (request, sender) => prompts.reveal(request, sender) },
            searchCredentialTargets: { handle: (request, sender) => prompts.search(request, sender) },
            chooseCredentialTarget: { handle: (request, sender) => prompts.choose(request, sender) },
            completeCredentialPrompt: {
                handle: (request, sender) => prompts.complete(request, sender),
                failure: operationFailure,
            },
            openSecurePicker: { handle: (request, sender) => pickers.open(request, sender) },
            getSecurePickerData: { handle: (request, sender) => pickers.dataWhenLoaded(request, sender) },
            completeSecurePicker: { handle: (request, sender) => pickers.complete(request, sender) },
            passkeyRequest: { handle: (request, sender) => passkeys.request(request, sender) },
            getPasskeyPromptData: { handle: (request, sender) => passkeys.data(request, sender) },
            completePasskeyPrompt: { handle: (request, sender) => passkeys.complete(request, sender) },
            cancelPasskeyRequest: { handle: (request, sender) => passkeys.cancel(request, sender) },
            popupLogins: { handle: (request, sender) => popup.logins(request, sender) },
            popupCopy: { handle: (request, sender) => popup.copy(request, sender) },
            popupSearch: { handle: (request, sender) => popup.search(request, sender) },
            popupCopyItem: { handle: (request, sender) => popup.copyItem(request, sender) },
            popupCopyGenerated: { handle: (request, sender) => popup.copyGenerated(request, sender) },
            popupFill: { handle: (request, sender) => popup.fill(request, sender) },
            popupSave: {
                handle: (request, sender) => popup.save(request, sender),
                failure: operationFailure,
            },
            claimPopupFill: { handle: (request, sender) => popup.claim(request, sender) },
        };

        function handleRequest(request, sender, sendResponse) {
            if (!request || typeof request !== "object" || typeof request.action !== "string") {
                sendResponse({ success: false, error: "Invalid extension request" });
                return false;
            }
            if (request.action === "acknowledgeUnknownOperation") {
                const trusted = security.securePickerSender(
                    sender,
                    chrome.runtime.id,
                    chrome.runtime.getURL("popup.html")
                );
                if (!trusted || request.inspected !== true || typeof request.operationId !== "string") {
                    sendResponse({ success: false, error: "Invalid operation acknowledgement" });
                    return false;
                }
                try {
                    sendResponse(acknowledgeUnknown(request.operationId));
                } catch (error) {
                    sendResponse({ success: false, error: error.message });
                }
                return false;
            }
            if (request.action === "reconcileOperation") {
                const trusted = ["popup.html", "credential_prompt.html"].some(path =>
                    security.securePickerSender(sender, chrome.runtime.id, chrome.runtime.getURL(path))
                );
                if (!trusted || typeof request.operationId !== "string") {
                    sendResponse({ success: false, error: "Invalid operation review" });
                    return false;
                }
                reconcile(request.operationId).then(sendResponse, error => sendResponse(errorResponse(error)));
                return true;
            }
            if (Object.hasOwn(serviceActions, request.action)) {
                const { handle, failure = errorResponse } = serviceActions[request.action];
                let result;
                try {
                    result = handle(request, sender);
                } catch (error) {
                    sendResponse(failure(error));
                    return false;
                }
                Promise.resolve(result).then(sendResponse, error => sendResponse(failure(error)));
                return true;
            }
            if (request.action === "getStatus") {
                refreshStatus()
                    .then(status => sendResponse({ ...status, pendingOperations: pendingOperations() }))
                    .catch(error =>
                        sendResponse({
                            native: false,
                            running: false,
                            locked: false,
                            error: error.message,
                        })
                    );
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
            if (request.action === "openDesktop") {
                const trusted = ["popup.html", "picker.html", "passkey_prompt.html"].some(path =>
                    security.securePickerSender(sender, chrome.runtime.id, chrome.runtime.getURL(path))
                );
                // Only the popup may name an item to open ("Open in desktop app").
                const item = request.id;
                const fromPopup = security.securePickerSender(
                    sender,
                    chrome.runtime.id,
                    chrome.runtime.getURL("popup.html")
                );
                const validItem = item === undefined || (fromPopup && Number.isSafeInteger(item) && item > 0);
                if (!trusted || !validItem) {
                    sendResponse({ success: false, error: "Invalid desktop launch request" });
                    return false;
                }
                sendAction("openDesktop", item === undefined ? {} : { entryId: item }, sendResponse);
                return true;
            }
            if (request.action === "lockVault") {
                const trusted = ["popup.html"].some(path =>
                    security.securePickerSender(sender, chrome.runtime.id, chrome.runtime.getURL(path))
                );
                if (!trusted || !contract.operations.lock.allowedSenders.some(role => ["popup"].includes(role))) {
                    sendResponse({ success: false, error: "Invalid lock request" });
                    return false;
                }
                pickers.invalidate();
                prompts.invalidate();
                duo.invalidate();
                passkeys.invalidate();
                popup?.invalidate();
                sendAction("lock", {}, sendResponse, true);
                return true;
            }
            sendResponse({ success: false, error: "Unsupported extension request" });
            return false;
        }
        // Keyboard shortcut: ask the focused frame to open the login picker.
        chrome.commands?.onCommand.addListener((command, tab) => {
            if (command !== "fill-login" || !Number.isSafeInteger(tab?.id)) return;
            chrome.tabs.sendMessage(tab.id, { action: "pmShortcutFill" }, () => void chrome.runtime.lastError);
        });
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            startup
                .then(() => handleRequest(request, sender, sendResponse))
                .catch(error => sendResponse({ success: false, error: error.message }));
            return true;
        });

        return {};
    },
};

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundRouter;
