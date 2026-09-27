const test = require("node:test");
const assert = require("node:assert/strict");
const state = require("./background_state.js");

test("every server state has stable badge semantics", () => {
    assert.deepEqual(state.badge({ native: false }), {
        text: "?", color: "#f59e0b", title: "Password Manager: native messaging host not installed"
    });
    assert.equal(state.badge({ native: true, running: false }).text, "N");
    assert.equal(state.badge({ native: true, running: true, locked: true }).text, "L");
    assert.equal(state.badge({ native: true, running: true, locked: false }).text, "U");
});

test("status equality includes user-visible errors", () => {
    const status = { native: true, running: false, locked: false, error: "offline" };
    assert.equal(state.equal(status, { ...status }), true);
    assert.equal(state.equal(status, { ...status, error: "missing host" }), false);
    assert.equal(state.equal(null, null), true);
});
