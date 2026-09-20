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

    function senderOrigin(sender) {
        try {
            const url = new URL(sender?.url || sender?.tab?.url || "");
            if (url.protocol !== "https:" && url.protocol !== "http:") return null;
            const host = url.hostname.toLowerCase().replace(/\.$/, "");
            return `${url.protocol}//${host}${url.port ? `:${url.port}` : ""}`;
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

    function securePickerSender(sender, extensionId, pickerUrl) {
        try {
            const senderUrl = new URL(sender?.url || "");
            const expected = new URL(pickerUrl);
            return sender?.id === extensionId
                && senderUrl.origin === expected.origin
                && senderUrl.pathname === expected.pathname;
        } catch (_) {
            return false;
        }
    }

    return { senderDomain, senderOrigin, pendingStorageKey, totpEntryAllowed, securePickerSender };
})();

if (typeof module !== "undefined") module.exports = PasswordManagerSecurity;
