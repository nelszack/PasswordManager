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
        // Change-password forms rarely show the username. With one saved login
        // for the site, the new password almost certainly belongs to it.
        const preferUpdate = !username && validAccounts.length === 1;
        const message = existing
            ? "An account with this username already exists. Update it or save a new account."
            : preferUpdate
              ? `Update the saved password for “${String(updateTarget.name || accountUsername(updateTarget) || "this login")}”, or save a new account.`
              : validAccounts.length
              ? "No saved account has this username. Update an existing account or save a new one."
              : "Would you like to save these credentials?";
        const targetUsername = updateTarget ? accountUsername(updateTarget) : "";
        const updateNote = noteFor(updateTarget, username, false);
        return {
            message,
            site,
            hasAccounts: validAccounts.length > 0,
            suggestedName,
            username: String(username || ""),
            askForUsername: !username,
            preferUpdate,
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

    // Updating a different account replaces only its password. Say so, because
    // the captured username is hidden and would otherwise look like it applies.
    // A login saved for another site also gains this site's address.
    function noteFor(target, username, addSite) {
        if (!target) return "";
        const targetUsername = accountUsername(target);
        const label = String(target.name || targetUsername || "this login");
        const notes = [];
        if (username && targetUsername !== username) {
            notes.push(
                `Updating “${label}” changes only its password` +
                    (targetUsername ? ` and keeps the username “${targetUsername}”.` : ".")
            );
        }
        if (addSite) notes.push(`This site's address will be added to “${label}”.`);
        return notes.join(" ");
    }

    // The person picked a saved login from a vault search, possibly one saved
    // for another site. `siteAccounts` are the logins already saved for this site.
    function chooseTarget(data, item, siteAccounts, username) {
        if (!Number.isSafeInteger(item?.id) || item.id <= 0) throw new Error("Choose a saved login");
        const addSite = !(Array.isArray(siteAccounts) && siteAccounts.some(account => account?.id === item.id));
        const target = {
            id: item.id,
            ...(item.revision === undefined ? {} : { revision: item.revision }),
            name: String(item.name || ""),
            username: accountUsername(item),
            addSite,
        };
        return {
            ...data,
            hasAccounts: true,
            preferUpdate: true,
            updateTarget: target,
            updateNote: noteFor(target, username, addSite),
            message: `Update the saved password for “${String(target.name || target.username || "this login")}”.`,
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
            if (pending.data.updateTarget.addSite === true) fields.addDomain = true;
        }
        return { action, fields };
    }

    return { accountUsername, accountsFromLookup, chooseTarget, describe, operation };
});
