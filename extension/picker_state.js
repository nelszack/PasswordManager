var PasswordManagerPickerState = (() => {
    const TITLES = {
        login: "Choose a login",
        totp: "Choose an authenticator",
        "payment-card": "Choose a payment card",
        identity: "Choose an identity",
    };
    function title(kind) {
        return TITLES[kind] || "Password Manager";
    }
    function itemLabel(item = {}) {
        return item.name || item.username || "Unnamed item";
    }
    function initial(item = {}) {
        const match = itemLabel(item).match(/[\p{L}\p{N}]/u);
        return match ? match[0].toUpperCase() : "•";
    }
    const EMPTY = {
        login: "No saved login matches this site yet. Save it when you sign in, or add it from the toolbar popup.",
        totp: "No login for this site has a one-time code. Add the code's setup key to the login in the desktop app.",
        "payment-card": "No payment cards are saved yet. Add one in the desktop app (Add item → Payment card).",
        identity: "No identities are saved yet. Add one in the desktop app (Add item → Identity).",
    };
    function status(items, kind = "login") {
        return Array.isArray(items) && items.length
            ? "Use ↑ ↓ and Enter, or click an item to fill it"
            : EMPTY[kind] || EMPTY.login;
    }
    // Which recovery a failure needs: unlock, reconnect, or reopen from the page.
    function failure(message = "") {
        if (/locked/i.test(message)) return "locked";
        if (/expired/i.test(message)) return "expired";
        if (/native|connect|host|not running|worker/i.test(message)) return "disconnected";
        return "other";
    }
    // Filter by query, then rank: name prefix, name substring, username match.
    function rank(items = [], query = "") {
        const needle = query.trim().toLowerCase();
        if (!needle) return items.slice();
        const score = item => {
            const name = itemLabel(item).toLowerCase();
            const username = String(item.username || "").toLowerCase();
            if (name.startsWith(needle)) return 0;
            if (name.includes(needle)) return 1;
            if (username.includes(needle)) return 2;
            return -1;
        };
        return items
            .map((item, index) => ({ item, index, score: score(item) }))
            .filter(entry => entry.score >= 0)
            .sort((a, b) => a.score - b.score || a.index - b.index)
            .map(entry => entry.item);
    }
    // Arrow-key movement that wraps; -1 means nothing is highlighted.
    function move(index, count, key) {
        if (!count) return -1;
        if (key === "ArrowDown") return index < 0 ? 0 : (index + 1) % count;
        if (key === "ArrowUp") return index <= 0 ? count - 1 : index - 1;
        if (key === "Home") return 0;
        if (key === "End") return count - 1;
        return index;
    }
    return {
        failure, title, itemLabel, initial, status, rank, move };
})();

if (typeof module !== "undefined") module.exports = PasswordManagerPickerState;
