var PasswordManagerPopupState = (() => {
    function presentation(status = {}) {
        if (!status.native) return { color: "#f59e0b", text: "Native host not installed", canLock: false };
        if (status.versionError) return {
            color: "#f59e0b", text: status.versionError,
            canLock: Boolean(status.running && !status.locked)
        };
        if (!status.running) return { color: "#6b7280", text: "Server not running", canLock: false };
        if (status.error) return { color: "#f59e0b", text: status.error, canLock: !status.locked };
        if (status.locked) return { color: "#ef4444", text: "Vault locked", canLock: false };
        return { color: "#22c55e", text: "Vault unlocked", canLock: true };
    }
    return { presentation };
})();

if (typeof module !== "undefined") module.exports = PasswordManagerPopupState;
