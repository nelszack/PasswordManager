(function (root, factory) {
    const api = factory();
    root.PasswordManagerCredentialPrompt = api;
    if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    "use strict";

    function accountUsername(account) {
        return account?.username && account.username !== "None" ? String(account.username) : "";
    }

    function hasExactMatch(accounts, username, password) {
        return Array.isArray(accounts) && accounts.some(account =>
            account?.password === password
            && (!username || accountUsername(account) === username)
        );
    }

    function describe(accounts, username, domain) {
        const validAccounts = Array.isArray(accounts)
            ? accounts.filter(account => Number.isSafeInteger(account?.id) && account.id > 0)
            : [];
        const existing = validAccounts.find(account => accountUsername(account) === username) || null;
        const updateTarget = existing || validAccounts[0] || null;
        let site = String(domain || "");
        let suggestedName = String(updateTarget?.name || "").trim();
        try {
            site = new URL(domain).origin;
        } catch (_) {
            // The background already validates page origins.
        }
        if (!suggestedName) {
            try {
                suggestedName = new URL(domain).hostname;
            } catch (_) {
                suggestedName = "";
            }
        }
        const message = existing
            ? "An account with this username already exists, but the password is different."
            : validAccounts.length
                ? "These credentials don't match any saved account."
                : "Would you like to save these credentials?";
        return {
            message,
            site,
            hasAccounts: validAccounts.length > 0,
            suggestedName,
            username: String(username || ""),
            askForUsername: !username,
            updateTarget: updateTarget
                ? { id: updateTarget.id, name: String(updateTarget.name || "") }
                : null
        };
    }

    function operation(pending, request) {
        const action = request?.action;
        if (action === "cancel") return { action };
        if (action !== "add" && action !== "update") {
            throw new Error("Invalid credential prompt action");
        }
        const username = typeof request.username === "string"
            ? request.username.trim()
            : pending.username;
        const name = typeof request.name === "string" ? request.name.trim() : "";
        if (!name) throw new Error("Enter a name for these credentials");
        const fields = {
            domain: pending.domain,
            username,
            password: pending.password,
            name
        };
        if (action === "update") {
            const entryId = pending.data?.updateTarget?.id;
            if (!Number.isSafeInteger(entryId) || entryId <= 0) {
                throw new Error("No credential is available to update");
            }
            fields.entryId = entryId;
        }
        return { action, fields };
    }

    return { accountUsername, hasExactMatch, describe, operation };
});
