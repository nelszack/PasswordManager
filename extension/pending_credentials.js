(function (root, factory) {
    const api = factory();
    root.PasswordManagerPendingCredentials = api;
    if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    "use strict";

    const MAX_AGE_MS = 60_000;

    function create(pending, domain, now = Date.now()) {
        if (!pending || typeof pending.password !== "string" || typeof domain !== "string") {
            throw new Error("Invalid pending credentials");
        }
        return {
            domain,
            username: String(pending.username || ""),
            password: pending.password,
            accountName: String(pending.accountName || ""),
            hasAccounts: Boolean(pending.hasAccounts),
            time: now
        };
    }

    function usable(record, domain, now = Date.now()) {
        return Boolean(record)
            && record.domain === domain
            && typeof record.password === "string"
            && Number.isFinite(record.time)
            && now >= record.time
            && now - record.time < MAX_AGE_MS;
    }

    return { MAX_AGE_MS, create, usable };
});
