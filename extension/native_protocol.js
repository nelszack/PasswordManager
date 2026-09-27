(function (root, factory) {
    const api = factory();
    root.PasswordManagerNativeProtocol = api;
    if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    "use strict";

    function validateResponse(response) {
        if (!response || !Number.isSafeInteger(response.id) || response.id <= 0
            || typeof response.success !== "boolean") {
            throw new Error("Invalid native host response");
        }
        if (response.success) {
            if (!("data" in response)) throw new Error("Invalid native host response");
        } else if (typeof response.error !== "string" || !response.error.trim()) {
            throw new Error("Invalid native host response");
        }
        return response;
    }

    function parseItems(response) {
        if (!response?.success) throw new Error(response?.error || "Vault items unavailable");
        if (typeof response.data !== "string") throw new Error("Invalid vault item response");
        let items;
        try {
            items = JSON.parse(response.data);
        } catch (_) {
            throw new Error("Invalid vault item response");
        }
        if (!Array.isArray(items)) throw new Error("Invalid vault item response");
        return items;
    }

    return { validateResponse, parseItems };
});
