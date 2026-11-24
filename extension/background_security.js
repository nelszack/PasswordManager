const PasswordManagerSecurity = (() => {
    // Normalized HTTP(S) origin of a URL the browser reported, such as a tab URL.
    function urlOrigin(value) {
        try {
            const url = new URL(typeof value === "string" ? value : "");
            if (url.protocol !== "https:" && url.protocol !== "http:") return null;
            const host = url.hostname.toLowerCase().replace(/\.$/, "");
            return `${url.protocol}//${host}${url.port ? `:${url.port}` : ""}`;
        } catch (_) {
            return null;
        }
    }

    // A message sender's security origin. Use the browser-computed origin, not the
    // document URL: a CSP-sandboxed document keeps its site's URL but has an opaque
    // ("null") origin, and a frame must never inherit its top-level tab's URL.
    function senderOrigin(sender) {
        const origin = sender?.origin;
        if (typeof origin !== "string" || origin === "null") return null;
        return urlOrigin(origin);
    }

    function pendingStorageKey(sender) {
        return Number.isInteger(sender?.tab?.id) ? `pmPopupPending:${sender.tab.id}` : null;
    }

    function securePickerSender(sender, extensionId, pickerUrl) {
        try {
            const senderUrl = new URL(sender?.url || "");
            const expected = new URL(pickerUrl);
            return (
                sender?.id === extensionId &&
                // Extension URLs have an opaque ("null") WHATWG origin. Compare
                // their scheme and authority rather than accepting any opaque URL.
                senderUrl.protocol === expected.protocol &&
                senderUrl.host === expected.host &&
                senderUrl.pathname === expected.pathname
            );
        } catch (_) {
            return false;
        }
    }

    return { senderOrigin, urlOrigin, pendingStorageKey, securePickerSender };
})();

module.exports = PasswordManagerSecurity;
