(function (root, factory) {
    const api = factory();
    root.PasswordManagerNativeProtocol = api;
    if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    "use strict";

    function validateResponse(response, expectedProtocolVersion, expectedOperationId) {
        if (expectedProtocolVersion !== undefined && response?.protocolVersion !== expectedProtocolVersion) {
            const error = new Error("Incompatible native protocol. Update the native host and extension together.");
            error.code = "protocol_mismatch"; throw error;
        }
        if (!response || !Number.isSafeInteger(response.id) || response.id <= 0
            || typeof response.success !== "boolean"
            || ("uncertain" in response && typeof response.uncertain !== "boolean")
            || (response.success && response.uncertain)) {
            throw new Error("Invalid native host response");
        }
        if (response.success) {
            if (!("data" in response)) throw new Error("Invalid native host response");
        } else if (typeof response.error !== "string" || !response.error.trim()) {
            throw new Error("Invalid native host response");
        }
        if (expectedOperationId && response.success) {
            const receipt = response.operation;
            if (!receipt || receipt.operationId !== expectedOperationId || receipt.state !== "committed"
                || !(receipt.revision === null || Number.isSafeInteger(receipt.revision) && receipt.revision >= 0)) {
                throw new Error("Invalid native mutation receipt");
            }
        }
        return response;
    }

    function parseItems(response) {
        if (!response?.success) throw new Error(response?.error || "Vault items unavailable");
        const items = response.data;
        if (!Array.isArray(items)) throw new Error("Invalid vault item response");
        return items;
    }

    return { validateResponse, parseItems };
});
