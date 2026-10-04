const test = require("node:test");
const assert = require("node:assert/strict");
const state = require("./background_state.js");

test("legacy and structured server status preserve explicit lock state and warnings", () => {
    // server warnings remain attached to otherwise healthy status
    {
        assert.deepEqual(
            state.parseServerStatus("Status: Locked\nVersion: 0.1.0"),
            { locked: true, serverVersion: "0.1.0" }
        );
        assert.deepEqual(
            state.parseServerStatus("Status: Unlocked\nVersion: 0.1.0\nWarning: Automatic lock failed: disk full"),
            { locked: false, serverVersion: "0.1.0", error: "Automatic lock failed: disk full" }
        );
    }
    // structured status uses explicit fields even when warning text mentions locks
    {
        assert.deepEqual(state.parseServerStatus({ locked: false, version: "0.1.0", warning: "Previous lock failed" }),
            { locked: false, serverVersion: "0.1.0", error: "Previous lock failed" });
        assert.deepEqual(state.parseServerStatus({ locked: true, version: "0.1.0", warning: null }),
            { locked: true, serverVersion: "0.1.0" });
        assert.deepEqual(state.parseServerStatus({ locked: true, version: "0.1.0", warning: "" }),
            { locked: true, serverVersion: "0.1.0" });
        for (const value of [null, [], 1, {}, { locked: "false", version: "0.1.0" },
            { locked: false, version: "" }, { locked: false, version: 1 },
            { locked: false, version: "0.1.0", warning: 1 }, "unlocked", "Status: unavailable\nVersion: 0.1.0"]) {
            assert.throws(() => state.parseServerStatus(value), /Invalid server status/);
        }
    }
});

test("component version mismatches identify every installed version", () => {
    assert.equal(state.versionError({
        running: true,
        extensionVersion: "0.1.0",
        nativeVersion: "0.1.0",
        serverVersion: "0.1.0"
    }), null);
    assert.equal(state.versionError({
        running: true,
        extensionVersion: "0.2.0",
        nativeVersion: "0.1.0",
        serverVersion: "0.1.0"
    }), "Version mismatch: extension 0.2.0, native host 0.1.0, password manager 0.1.0. Update all Password Manager components together.");
    assert.match(state.versionError({
        running: true,
        extensionVersion: "0.1.0",
        nativeVersion: "0.1.0"
    }), /password manager version unavailable/);
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
    assert.equal(state.badge({ native: true, versionError: "Versions differ" }).text, "!");
});

test("status equality includes user-visible errors", () => {
    const status = { native: true, running: false, locked: false, error: "offline" };
    assert.equal(state.equal(status, { ...status }), true);
    assert.equal(state.equal(status, { ...status, error: "missing host" }), false);
    assert.equal(state.equal(status, { ...status, versionError: "Versions differ" }), false);
    assert.equal(state.equal(null, null), true);
});
