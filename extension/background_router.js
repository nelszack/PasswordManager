// Own state per worker instance; browser services are supplied by background.js.
const PasswordManagerBackgroundRouter = {
    create({ chrome, security, contract, nativeRequest, reconcile, pendingOperations = () => [], acknowledgeUnknown, startup = Promise.resolve(), refreshStatus, pickers, prompts, pendingCredentials, duo }) {
        function sendAction(action, fields, sendResponse, refreshAfter = false) {
            nativeRequest(action, fields)
                .then(response => {
                    sendResponse(response.success
                        ? { success: true, data: response.data, operation: response.operation }
                        : { success: false, error: response.error, uncertain: Boolean(response.uncertain), operationId: response.operationId, operationAction: response.operationAction, code: response.code });
                    if (refreshAfter) refreshStatus();
                })
                .catch(error => {
                    sendResponse({ success: false, error: error.message, uncertain: Boolean(error.uncertain), operationId: error.operationId, operationAction: error.operationAction });
                    if (refreshAfter) refreshStatus();
                });
        }

        function handleRequest(request, sender, sendResponse) {
            if (!request || typeof request !== "object" || typeof request.action !== "string") {
                sendResponse({ success: false, error: "Invalid extension request" }); return false;
            }
            if (request.action === "acknowledgeUnknownOperation") {
                const trusted = security.securePickerSender(sender, chrome.runtime.id, chrome.runtime.getURL("manager.html"));
                if (!trusted || request.inspected !== true || typeof request.operationId !== "string") { sendResponse({ success: false, error: "Invalid operation acknowledgement" }); return false; }
                try { sendResponse(acknowledgeUnknown(request.operationId)); }
                catch (error) { sendResponse({ success: false, error: error.message }); }
                return false;
            }
            if (request.action === "reconcileOperation") {
                const trusted = ["manager.html", "credential_prompt.html"].some(path => security.securePickerSender(sender, chrome.runtime.id, chrome.runtime.getURL(path)));
                if (!trusted || typeof request.operationId !== "string") { sendResponse({ success: false, error: "Invalid operation review" }); return false; }
                reconcile(request.operationId).then(sendResponse).catch(error => sendResponse({ success: false, error: error.message }));
                return true;
            }
            const duoActions = { observeDuoChallenge: "observe", getDuoPromptData: "data", completeDuoPrompt: "complete" };
            if (Object.hasOwn(duoActions, request.action)) {
                duo[duoActions[request.action]](request, sender).then(sendResponse)
                    .catch(error => sendResponse({ success: false, error: error.message }));
                return true;
            }
            if (typeof request.action === "string" && request.action.startsWith("manager")) {
                const trusted = security.securePickerSender(sender, chrome.runtime.id, chrome.runtime.getURL("manager.html"));
                const policy = contract.operations[request.action];
                if (!trusted || !policy?.allowedSenders.includes("manager")) {
                    sendResponse({ success: false, error: "Invalid vault management request" });
                    return false;
                }
                const { action, ...fields } = request;
                sendAction(action, fields, sendResponse, policy.mutates);

                return true;
            }
            if (request.action === "openCredentialPrompt") {
                prompts.open(request, sender)
                    .then(sendResponse)
                    .catch(error => sendResponse({ success: false, error: error.message }));
                return true;
            }
            if (request.action === "reviewCredentialPrompt") {
                prompts.review(request, sender).then(sendResponse).catch(error => sendResponse({ success: false, error: error.message }));
                return true;
            }
            if (request.action === "getCredentialPromptData") {
                sendResponse(prompts.data(request, sender));
                return true;
            }
            if (request.action === "completeCredentialPrompt") {
                prompts.complete(request, sender)
                    .then(sendResponse)
                    .catch(error => sendResponse({ success: false, error: error.message, uncertain: Boolean(error.uncertain), operationId: error.operationId, operationAction: error.operationAction }));
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
                    .then(status => sendResponse({ ...status, pendingOperations: pendingOperations() }))
                    .catch(error => sendResponse({
                        native: false,
                        running: false,
                        locked: false,
                        error: error.message
                    }));
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
                const trusted = ["popup.html", "manager.html"].some(path => security.securePickerSender(sender, chrome.runtime.id, chrome.runtime.getURL(path)));
                if (!trusted || !contract.operations.lock.allowedSenders.some(role => ["popup", "manager"].includes(role))) { sendResponse({ success: false, error: "Invalid lock request" }); return false; }
                pickers.invalidate();
                prompts.invalidate();
                duo.invalidate();
                sendAction("lock", {}, sendResponse, true);
                return true;
            }
            sendResponse({ success: false, error: "Unsupported extension request" });
            return false;
        }
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            startup.then(() => handleRequest(request, sender, sendResponse))
                .catch(error => sendResponse({ success: false, error: error.message }));
            return true;
        });

        return {};
    }
};

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundRouter;
