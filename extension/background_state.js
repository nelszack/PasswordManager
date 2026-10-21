var PasswordManagerBackgroundState = (() => {
    function parseServerStatus(value) {
        if (value && typeof value === "object" && !Array.isArray(value)) {
            if (typeof value.locked !== "boolean" || typeof value.version !== "string"
                || !value.version || (value.warning != null && typeof value.warning !== "string")) {
                throw new Error("Invalid server status");
            }
            return {
                locked: value.locked,
                serverVersion: value.version,
                ...(value.warning ? { error: value.warning } : {})
            };
        }
        throw new Error("Invalid server status");
    }

    function versionError(status = {}) {
        if (!Number.isSafeInteger(status.protocolVersion) || status.protocolVersion !== status.extensionProtocolVersion) {
            return "Incompatible native protocol. Update the native host and extension together.";
        }
        return null;
    }

    function badge(status) {
        if (!status?.native) {
            return { text: "?", color: "#f59e0b", title: "Password Manager: native messaging host not installed" };
        }
        if (status.versionError) {
            return { text: "!", color: "#f59e0b", title: `Password Manager: ${status.versionError}` };
        }
        if (!status.running) {
            return { text: "N", color: "#6b7280", title: "Password Manager: server not running" };
        }
        if (status.error) {
            return { text: "!", color: "#f59e0b", title: `Password Manager: ${status.error}` };
        }
        if (status.locked) {
            return { text: "L", color: "#ef4444", title: "Password Manager: vault locked" };
        }
        return { text: "U", color: "#22c55e", title: "Password Manager: vault unlocked" };
    }

    function equal(left, right) {
        return left?.native === right?.native
            && left?.running === right?.running
            && left?.locked === right?.locked
            && left?.sessionId === right?.sessionId
            && left?.error === right?.error
            && left?.versionError === right?.versionError
            && left?.extensionVersion === right?.extensionVersion
            && left?.nativeVersion === right?.nativeVersion
            && left?.protocolVersion === right?.protocolVersion
            && left?.serverVersion === right?.serverVersion;
    }

    return { parseServerStatus, versionError, badge, equal };
})();

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundState;
