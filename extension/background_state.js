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
        // Compatibility with native hosts installed before structured status.
        if (typeof value !== "string") throw new Error("Invalid server status");
        const match = /^Status: (Locked|Unlocked)\nVersion: ([^\s]+)(?:\nWarning: ([\s\S]*))?$/i.exec(value);
        if (!match) throw new Error("Invalid server status");
        return { locked: match[1].toLowerCase() === "locked", serverVersion: match[2],
            ...(match[3] ? { error: match[3] } : {}) };
    }

    function versionError(status = {}) {
        const versions = [
            ["extension", status.extensionVersion],
            ["native host", status.nativeVersion],
            ...(status.running ? [["password manager", status.serverVersion]] : [])
        ];
        const missing = versions.filter(([, version]) => !version).map(([name]) => name);
        if (missing.length) {
            return `Version mismatch: ${missing.join(" and ")} version unavailable. Update all Password Manager components together.`;
        }
        if (new Set(versions.map(([, version]) => version)).size <= 1) return null;
        return `Version mismatch: ${versions.map(([name, version]) => `${name} ${version}`).join(", ")}. Update all Password Manager components together.`;
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
            && left?.error === right?.error
            && left?.versionError === right?.versionError
            && left?.extensionVersion === right?.extensionVersion
            && left?.nativeVersion === right?.nativeVersion
            && left?.serverVersion === right?.serverVersion;
    }

    return { parseServerStatus, versionError, badge, equal };
})();

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundState;
