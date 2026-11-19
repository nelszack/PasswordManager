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
    function status(items) {
        return Array.isArray(items) && items.length
            ? "Use ↑ ↓ and Enter, or click an item to fill it"
            : "No saved items match this site";
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
    return { title, itemLabel, initial, status, rank, move };
})();

if (typeof module !== "undefined") module.exports = PasswordManagerPickerState;
