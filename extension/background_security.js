const PasswordManagerSecurity = (() => {
    function senderDomain(sender) {
        try {
            const url = new URL(sender?.url || sender?.tab?.url || "");
            if (url.protocol !== "https:" && url.protocol !== "http:") return null;
            return url.hostname.toLowerCase().replace(/\.$/, "");
        } catch (_) {
            return null;
        }
    }

    function pendingStorageKey(sender) {
        return Number.isInteger(sender?.tab?.id) ? `pmPopupPending:${sender.tab.id}` : null;
    }

    function totpEntryAllowed(accounts, entryId) {
        return Array.isArray(accounts)
            && Number.isSafeInteger(entryId)
            && entryId > 0
            && accounts.some(account => account?.id === entryId && account.has_totp === true);
    }

    return { senderDomain, pendingStorageKey, totpEntryAllowed };
})();

if (typeof module !== "undefined") module.exports = PasswordManagerSecurity;
