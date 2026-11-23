(function (root, factory) {
    const api = factory();
    root.PasswordManagerCredentialPrompt = api;
    if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    "use strict";

    function accountUsername(account) {
        return account?.username ? String(account.username) : "";
    }

    function accountsFromLookup(response) {
        if (!response?.success) {
            const error = String(response?.error || "Credentials unavailable").trim();
            // The server uses NotFound when a URL has no credentials. For a
            // save prompt that is the expected new-site state, not a failure.
            if (/^not found\.?$/i.test(error)) return [];
            throw new Error(error);
        }
        const accounts = response.data;
        if (!Array.isArray(accounts)) throw new Error("Invalid credential response");
        return accounts;
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
            ? "An account with this username already exists. Update it or save a new account."
            : validAccounts.length
              ? "No saved account has this username. Update an existing account or save a new one."
              : "Would you like to save these credentials?";
        const targetUsername = updateTarget ? accountUsername(updateTarget) : "";
        // Updating a different account replaces only its password. Say so, because
        // the captured username is hidden and would otherwise look like it applies.
        const updateNote =
            updateTarget && username && targetUsername !== username
                ? `Updating “${String(updateTarget.name || targetUsername || "this login")}” changes only its password` +
                  (targetUsername ? ` and keeps the username “${targetUsername}”.` : ".")
                : "";
        return {
            message,
            site,
            hasAccounts: validAccounts.length > 0,
            suggestedName,
            username: String(username || ""),
            askForUsername: !username,
            updateNote,
            updateTarget: updateTarget
                ? {
                      id: updateTarget.id,
                      ...(updateTarget.revision === undefined ? {} : { revision: updateTarget.revision }),
                      name: String(updateTarget.name || ""),
                      username: targetUsername,
                  }
                : null,
        };
    }

    function operation(pending, request) {
        const action = request?.action;
        if (action === "cancel") return { action };
        if (action !== "add" && action !== "update") {
            throw new Error("Invalid credential prompt action");
        }
        const username = typeof request.username === "string" ? request.username.trim() : pending.username;
        const name = typeof request.name === "string" ? request.name.trim() : "";
        if (!name) throw new Error("Enter a name for these credentials");
        // The person may correct the captured password after revealing it.
        let password = pending.password;
        if (request.password !== undefined) {
            if (
                typeof request.password !== "string" ||
                !request.password ||
                request.password.length > 64 * 1024 ||
                /[\0\r\n]/.test(request.password)
            )
                throw new Error("Enter the password to save");
            password = request.password;
        }
        const fields = {
            domain: pending.domain,
            expectedSession: pending.sessionId,
            username,
            password,
            name,
        };
        if (action === "update") {
            const entryId = pending.data?.updateTarget?.id;
            if (!Number.isSafeInteger(entryId) || entryId <= 0) {
                throw new Error("No credential is available to update");
            }
            delete fields.name;
            // Keep the target's stored username unless the user explicitly entered
            // a different one; a captured username for another account must never
            // silently rename the account being updated.
            const targetUsername = pending.data.updateTarget.username;
            const captured = String(pending.username || "").trim();
            if (typeof targetUsername === "string" && username === captured) fields.username = targetUsername;
            fields.entryId = entryId;
            fields.expectedRevision = pending.data.updateTarget.revision;
        }
        return { action, fields };
    }

    return { accountUsername, accountsFromLookup, describe, operation };
});
