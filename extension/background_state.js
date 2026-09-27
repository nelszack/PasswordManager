var PasswordManagerBackgroundState = (() => {
    function parseServerStatus(value) {
        const data = String(value);
        const warning = data.split("\nWarning: ", 2)[1];
        return {
            locked: /\blocked\b/i.test(data),
            ...(warning ? { error: warning } : {})
        };
    }

    function badge(status) {
        if (!status?.native) {
            return { text: "?", color: "#f59e0b", title: "Password Manager: native messaging host not installed" };
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
            && left?.error === right?.error;
    }

    return { parseServerStatus, badge, equal };
})();

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundState;
