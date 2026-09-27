const test = require("node:test");
const assert = require("node:assert/strict");
const state = require("./background_state.js");

test("server warnings remain attached to otherwise healthy status", () => {
    assert.deepEqual(state.parseServerStatus("Status: Locked"), { locked: true });
    assert.deepEqual(
        state.parseServerStatus("Status: Unlocked\nWarning: Automatic lock failed: disk full"),
        { locked: false, error: "Automatic lock failed: disk full" }
    );
});

test("every server state has stable badge semantics", () => {
    assert.deepEqual(state.badge({ native: false }), {
        text: "?", color: "#f59e0b", title: "Password Manager: native messaging host not installed"
    });
    assert.equal(state.badge({ native: true, running: false }).text, "N");
    assert.equal(state.badge({ native: true, running: true, locked: true }).text, "L");
    assert.equal(state.badge({ native: true, running: true, locked: false }).text, "U");
    assert.deepEqual(
        state.badge({ native: true, running: true, locked: false, error: "Automatic lock failed" }),
        { text: "!", color: "#f59e0b", title: "Password Manager: Automatic lock failed" }
    );
});

test("status equality includes user-visible errors", () => {
    const status = { native: true, running: false, locked: false, error: "offline" };
    assert.equal(state.equal(status, { ...status }), true);
    assert.equal(state.equal(status, { ...status, error: "missing host" }), false);
    assert.equal(state.equal(null, null), true);
});
