var PasswordManagerPickerState = (() => {
    const TITLES = {
        login: "Choose saved credentials",
        totp: "Choose authenticator",
        "payment-card": "Choose payment card",
        identity: "Choose identity"
    };
    function title(kind) {
        return TITLES[kind] || "Password Manager";
    }
    function itemLabel(item = {}) {
        return item.name || item.username || "Unnamed item";
    }
    function status(items) {
        return Array.isArray(items) && items.length ? "Select an item to fill" : "No matching items";
    }
    return { title, itemLabel, status };
})();

if (typeof module !== "undefined") module.exports = PasswordManagerPickerState;
