var PasswordManagerPopupState = (() => {
    function presentation(status = {}) {
        if (!status.native) return { color: "#f59e0b", text: "Browser connection not set up", canLock: false };
        if (status.versionError)
            return {
                color: "#f59e0b",
                text: status.versionError,
                canLock: Boolean(status.running && !status.locked),
            };
        if (!status.running) return { color: "#6b7280", text: "Desktop app not running", canLock: false };
        if (status.error) return { color: "#f59e0b", text: status.error, canLock: !status.locked };
        if (status.locked) return { color: "#ef4444", text: "Vault locked", canLock: false };
        return { color: "#22c55e", text: "Vault unlocked", canLock: true };
    }
    function hint(status = {}) {
        if (!status.native) return "Open the desktop app and turn on browser integration in Tools.";
        if (!status.running) return "Open the desktop app to start it and unlock your vault.";
        if (status.locked) return "Unlock your vault in the desktop app to fill and save logins.";
        return "Click the key button in a website’s login field to fill a saved account.";
    }
    const ACTIONS = {
        saveCredentials: "Saving a new login",
        updateCredentials: "Updating a saved login",
        lockVault: "Locking the vault",
    };
    // Plain-language label; the short ID suffix still distinguishes repeats.
    function operationLabel(record = {}) {
        const action =
            ACTIONS[record.action] ||
            String(record.action || "Change")
                .replace(/([a-z])([A-Z])/g, "$1 $2")
                .replace(/^./, c => c.toUpperCase());
        return `${action} (#${String(record.operationId || "").slice(-6)})`;
    }
    // Popup controls cover the common choices; everything else keeps its saved value.
    function generatorSettings(stored, changes = {}) {
        const settings = { ...(stored && typeof stored === "object" ? stored : {}), ...changes };
        if ("passphrase" in changes) {
            settings.mode = changes.passphrase ? "passphrase" : "password";
            delete settings.passphrase;
        }
        return settings;
    }
    function neverSaveSites(value) {
        return Array.isArray(value) ? value.filter(site => typeof site === "string" && site) : [];
    }
    return { presentation, hint, operationLabel, generatorSettings, neverSaveSites };
})();

if (typeof module !== "undefined") module.exports = PasswordManagerPopupState;
