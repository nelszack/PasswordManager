const test = require("node:test");
const assert = require("node:assert/strict");
const {
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
} = require("./popup_state.js");

test("popup renders disconnected, stopped, locked, and unlocked states", () => {
    assert.deepEqual(presentation(), { tone: "warning", text: "Not connected", canLock: false });
    assert.equal(presentation({ native: true }).text, "Service stopped");
    assert.equal(presentation({ native: true, running: true, locked: true }).text, "Locked");
    assert.deepEqual(presentation({ native: true, running: true, locked: false }), {
        tone: "success", text: "Unlocked", canLock: true
    });
    assert.deepEqual(
        presentation({ native: true, running: true, locked: false, error: "Automatic lock failed" }),
        { tone: "warning", text: "Needs attention", canLock: true }
    );
    assert.deepEqual(
        presentation({ native: true, running: true, locked: false, versionError: "Versions differ" }),
        { tone: "warning", text: "Update needed", canLock: true }
    );
});

test("popup hints and the desktop button name the next step for each state", () => {
    const locked = { native: true, running: true, locked: true };
    assert.match(hint(), /Connect this browser/);
    assert.match(hint({ native: true }), /start it/);
    assert.match(hint(locked), /Unlock/);
    assert.equal(hint({ native: true, running: true }), "");
    assert.match(hint({ native: true, running: true, error: "Automatic lock failed" }), /Automatic lock failed/);
    assert.match(hint({ native: true, versionError: "Versions differ." }), /Update the desktop app/);
    assert.match(hint({ transportError: "gone" }), /reconnecting automatically/);
    // While locked, the button sends you to the desktop app to unlock.
    assert.equal(desktopLabel(locked), "Unlock in desktop app");
    assert.equal(desktopLabel({ ...locked, locked: false }), "Open desktop app");
    assert.equal(desktopLabel({ ...locked, versionError: "mismatch" }), "Open desktop app");
    assert.equal(desktopLabel(), "Open desktop app");
});

test("setup names the command for this browser family", () => {
    assert.match(setupCommand("Mozilla/5.0 Firefox/130.0"), /--browser firefox$/);
    assert.match(setupCommand("Chrome/130 Chromium/130"), /--browser chromium$/);
    assert.match(setupCommand("Mozilla/5.0 Chrome/130"), /--browser chrome$/);
    assert.match(setupCommand(), /--browser chrome$/);
});

test("site messages explain empty, insecure, and unsupported pages", () => {
    assert.match(siteMessage({ reason: "insecure", host: "http://router.local" }), /not encrypted/);
    assert.match(siteMessage({ reason: "unsupported" }), /Open a website/);
    assert.equal(siteMessage({ error: "Vault locked" }), "Vault locked");
    assert.match(siteMessage({ site: "https://example.com", items: [] }), /example\.com yet/);
    assert.equal(siteMessage({ site: "https://example.com", items: [{}] }), "");
    assert.equal(hostOf("not a url"), "this site");
});

test("site logins filter by name or username and shortcuts read naturally", () => {
    const items = [
        { name: "Work", username: "w@corp" },
        { name: "Personal", username: "me@home" },
    ];
    assert.deepEqual(filterLogins(items, "  "), items);
    assert.deepEqual(filterLogins(items, "HOME"), [items[1]]);
    assert.deepEqual(filterLogins(undefined, "x"), []);
    assert.equal(
        shortcutText([
            { name: "_execute_action", shortcut: "Ctrl+Shift+Y" },
            { name: "fill-login", shortcut: "Ctrl+Shift+L" },
            { name: "other", shortcut: "X" },
            { name: "fill-login", shortcut: "" },
        ]),
        "Shortcuts — Open: Ctrl+Shift+Y · Fill login: Ctrl+Shift+L"
    );
    assert.equal(shortcutText([]), "");
});

test("pending operations get plain-language labels with a short ID", () => {
    assert.equal(operationLabel({ action: "saveCredentials", operationId: "abc-123456" }), "A login save may not have finished (#123456)");
    assert.equal(operationLabel({ action: "restoreTrash", operationId: "x1" }), "Restore Trash (#x1)");
    assert.equal(operationLabel(), "Change (#)");
});

test("popup generator settings merge into stored settings", () => {
    assert.deepEqual(generatorSettings(null, { length: 24 }), { length: 24 });
    assert.deepEqual(generatorSettings({ length: 24, symbolSet: "!" }, { passphrase: true }), {
        length: 24, symbolSet: "!", mode: "passphrase"
    });
    assert.deepEqual(generatorSettings({ mode: "passphrase" }, { passphrase: false }), { mode: "password" });
    assert.deepEqual(neverSaveSites(["https://a.test", 4, ""]), ["https://a.test"]);
    assert.deepEqual(neverSaveSites("x"), []);
});
