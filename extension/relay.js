(function (root, factory) {
    const api = factory();
    root.PasswordManagerRelay = api;
    if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    "use strict";

    const TOKEN_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    const RESULT_ACTIONS = new Set(["add", "update", "cancel", "ignore"]);

    function requestRoute(data, sender) {
        const tabId = sender?.tab?.id;
        const sourceFrameId = sender?.frameId;
        let senderOrigin;
        try {
            const url = new URL(sender?.url);
            if (url.protocol !== "https:" && url.protocol !== "http:") return null;
            senderOrigin = url.origin.toLowerCase();
        } catch (_) {
            return null;
        }
        if (tabId == null || !Number.isInteger(sourceFrameId) || sourceFrameId <= 0
            || senderOrigin !== data?.domain
            || !TOKEN_RE.test(data?.token || "")
            || typeof data?.username !== "string"
            || typeof data?.password !== "string") {
            return null;
        }
        return {
            tabId,
            frameId: 0,
            message: { action: "relayedLogin", sourceFrameId, data }
        };
    }

    function resultRoute(request, sender) {
        const tabId = sender?.tab?.id;
        const sourceFrameId = request?.sourceFrameId;
        const data = request?.data;
        if (tabId == null || sender?.frameId !== 0
            || !Number.isInteger(sourceFrameId) || sourceFrameId <= 0
            || !TOKEN_RE.test(data?.token || "")
            || !RESULT_ACTIONS.has(data?.action)) {
            return null;
        }
        return {
            tabId,
            frameId: sourceFrameId,
            message: { action: "relayedLoginResult", data }
        };
    }


    function relayKey(tabId, token) {
        return `${tabId}:${token}`;
    }

    function authorizeCredentialRequest(request, sender, pendingRelays, consume = false) {
        const tabId = sender?.tab?.id;
        if (tabId == null || sender?.frameId !== 0 || !TOKEN_RE.test(request?.token || "")) {
            return null;
        }
        const key = relayKey(tabId, request.token);
        const relay = pendingRelays.get(key);
        if (!relay || relay.sourceFrameId !== request.sourceFrameId || relay.expiresAt <= Date.now()) {
            pendingRelays.delete(key);
            return null;
        }
        if (consume) pendingRelays.delete(key);
        return relay;
    }

    return { requestRoute, resultRoute, relayKey, authorizeCredentialRequest };
});
