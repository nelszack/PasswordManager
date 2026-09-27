const test = require("node:test");
const assert = require("node:assert/strict");
const { presentation } = require("./popup_state.js");

test("popup renders disconnected, stopped, locked, and unlocked states", () => {
    assert.deepEqual(presentation(), { color: "#f59e0b", text: "Native host not installed", canLock: false });
    assert.equal(presentation({ native: true }).text, "Server not running");
    assert.equal(presentation({ native: true, running: true, locked: true }).text, "Vault locked");
    assert.deepEqual(presentation({ native: true, running: true, locked: false }), {
        color: "#22c55e", text: "Vault unlocked", canLock: true
    });
});
