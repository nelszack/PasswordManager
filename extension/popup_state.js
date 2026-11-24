var PasswordManagerPopupState = (() => {
    // `tone` selects a theme colour and dot shape in popup.css.
    function presentation(status = {}) {
        if (status.transportError) return { tone: "warning", text: "Reconnecting…", canLock: false };
        if (!status.native) return { tone: "warning", text: "Not connected", canLock: false };
        if (status.versionError)
            return {
                tone: "warning",
                text: "Update needed",
                canLock: Boolean(status.running && !status.locked),
            };
        if (!status.running) return { tone: "muted", text: "Service stopped", canLock: false };
        if (status.error) return { tone: "warning", text: "Needs attention", canLock: !status.locked };
        // Locked is a normal state, not a problem.
        if (status.locked) return { tone: "locked", text: "Locked", canLock: false };
        return { tone: "success", text: "Unlocked", canLock: true };
    }
    // One sentence naming the next step; known problems in plain language.
    function hint(status = {}) {
        if (status.transportError)
            return "The extension restarted; reconnecting automatically. Choose Reconnect if this persists.";
        if (!status.native) return "Connect this browser to the desktop app to fill and save logins.";
        if (status.versionError)
            return `${status.versionError} Update the desktop app or this extension so their versions match.`;
        if (!status.running)
            return "The background service isn't running. Open the desktop app to start it and unlock your vault.";
        if (status.error) return `The desktop app reported: ${status.error}`;
        if (status.locked) return "Unlock your vault in the desktop app; this popup updates by itself.";
        return "";
    }
    const ACTIONS = {
        saveCredentials: "A login save may not have finished",
        updateCredentials: "A login update may not have finished",
        lockVault: "Locking may not have finished",
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
    // While locked, the desktop app is where you unlock.
    function desktopLabel(status = {}) {
        return status.native && status.running && !status.versionError && status.locked
            ? "Unlock in desktop app"
            : "Open desktop app";
    }
    // The registration command for this browser family.
    function setupCommand(userAgent = "") {
        if (/Firefox\//.test(userAgent)) return "pm native-host install --browser firefox";
        if (/Chromium\//.test(userAgent)) return "pm native-host install --browser chromium";
        return "pm native-host install --browser chrome";
    }
    // Why a page has no logins listed, with what to do about it.
    function siteMessage(site = {}) {
        if (site.reason === "insecure")
            return `Autofill is off on ${site.host} because the page is not encrypted (http).`;
        if (site.reason === "unsupported") return "Open a website to see the logins saved for it.";
        if (site.error) return site.error;
        if (!site.items?.length)
            return `No logins are saved for ${hostOf(site.site)} yet. Use Add above, or search all items below.`;
        return "";
    }
    function hostOf(origin) {
        try {
            return new URL(origin).host;
        } catch (_) {
            return "this site";
        }
    }
    function filterLogins(items = [], query = "") {
        const needle = query.trim().toLowerCase();
        if (!needle) return items;
        return items.filter(item => `${item.name} ${item.username}`.toLowerCase().includes(needle));
    }
    // Whether every vault action is usable: connected, running, unlocked, current.
    function usable(status = {}) {
        return Boolean(
            status.native && status.running && !status.locked && !status.versionError && !status.transportError
        );
    }
    // Copying without the desktop service cannot clear the clipboard, so only an
    // unreachable service (never a refusal such as "copying is off") allows it.
    function canCopyLocally(status = {}) {
        return Boolean(status.transportError || !status.native || !status.running);
    }
    // A readable shortcut list from chrome.commands.getAll().
    function shortcutText(commands = []) {
        const labels = { _execute_action: "Open", "fill-login": "Fill login" };
        const parts = commands
            .filter(command => labels[command.name] && command.shortcut)
            .map(command => `${labels[command.name]}: ${command.shortcut}`);
        return parts.length ? `Shortcuts — ${parts.join(" · ")}` : "";
    }
    return {
        presentation,
        hint,
        operationLabel,
        generatorSettings,
        neverSaveSites,
        desktopLabel,
        setupCommand,
        siteMessage,
        hostOf,
        filterLogins,
        shortcutText,
        usable,
        canCopyLocally,
    };
})();

module.exports = PasswordManagerPopupState;
