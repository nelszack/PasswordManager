const test = require("node:test");
const assert = require("node:assert/strict");
const { presentation, hint, operationLabel, generatorSettings, neverSaveSites, desktopLabel } = require("./popup_state.js");

test("popup renders disconnected, stopped, locked, and unlocked states", () => {
    assert.deepEqual(presentation(), { color: "#f59e0b", text: "Browser connection not set up", canLock: false });
    assert.equal(presentation({ native: true }).text, "Desktop app not running");
    assert.equal(presentation({ native: true, running: true, locked: true }).text, "Vault locked");
    assert.deepEqual(presentation({ native: true, running: true, locked: false }), {
        color: "#22c55e", text: "Vault unlocked", canLock: true
    });
    assert.deepEqual(
        presentation({ native: true, running: true, locked: false, error: "Automatic lock failed" }),
        { color: "#f59e0b", text: "Automatic lock failed", canLock: true }
    );
    assert.deepEqual(
        presentation({ native: true, running: true, locked: false, versionError: "Versions differ" }),
        { color: "#f59e0b", text: "Versions differ", canLock: true }
    );
});

test("popup hints and the desktop button name the next step for each state", () => {
    const locked = { native: true, running: true, locked: true };
    assert.match(hint(), /browser integration/);
    assert.match(hint({ native: true }), /start it/);
    assert.match(hint(locked), /Unlock/);
    assert.match(hint({ native: true, running: true }), /key button/);
    // While locked, the button sends you to the desktop app to unlock.
    assert.equal(desktopLabel(locked), "Unlock in desktop app");
    assert.equal(desktopLabel({ ...locked, locked: false }), "Open desktop app");
    assert.equal(desktopLabel({ ...locked, versionError: "mismatch" }), "Open desktop app");
    assert.equal(desktopLabel(), "Open desktop app");
});

test("pending operations get plain-language labels with a short ID", () => {
    assert.equal(operationLabel({ action: "saveCredentials", operationId: "abc-123456" }), "Saving a new login (#123456)");
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
