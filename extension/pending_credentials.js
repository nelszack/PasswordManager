(function (root, factory) {
    const api = factory();
    root.PasswordManagerPendingCredentials = api;
    if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    "use strict";

    const MAX_AGE_MS = 60_000;

    function create(pending, domain, now = Date.now()) {
        if (!pending || typeof pending !== "object" || Array.isArray(pending)
            || typeof pending.username !== "string" || !pending.username || pending.username.length > 4096
            || "password" in pending || typeof domain !== "string") {
            throw new Error("Invalid pending credentials");
        }
        return {
            domain,
            username: String(pending.username || ""),
            time: now
        };
    }

    function usable(record, domain, now = Date.now()) {
        return Boolean(record)
            && typeof record === "object" && !Array.isArray(record)
            && record.domain === domain
            && typeof record.username === "string" && record.username.length > 0 && record.username.length <= 4096 && !("password" in record)
            && Number.isFinite(record.time)
            && now >= record.time
            && now - record.time < MAX_AGE_MS;
    }

    return { MAX_AGE_MS, create, usable };
});
