const test = require("node:test");
const assert = require("node:assert/strict");
const { create } = require("./content_bridge.js");

function environment() {
    let listener;
    const callbacks = [];
    const timers = new Set();
    const originalSetTimeout = global.setTimeout;
    const originalClearTimeout = global.clearTimeout;
    global.setTimeout = fn => { timers.add(fn); return fn; };
    global.clearTimeout = fn => timers.delete(fn);
    global.chrome = { runtime: {
        sendMessage(message, callback) { callbacks.push({ message, callback }); },
        onMessage: { addListener(fn) { listener = fn; }, removeListener() {} }
    } };
    const bridge = create();
    return { bridge, callbacks, timers,
        deliver(message) { listener(message); },
        cleanup() {
            bridge.dispose();
            global.setTimeout = originalSetTimeout;
            global.clearTimeout = originalClearTimeout;
            delete global.chrome;
        }
    };
}

for (const kind of ["picker", "prompt"]) test(`${kind} receives results arriving before the opening response`, async () => {
    const env = environment();
    try {
        const pending = kind === "picker" ? env.bridge.openSecurePicker("identity")
            : env.bridge.openCredentialPrompt("alice", "synthetic");
        const result = kind === "picker" ? { kind: "identity" } : { action: "add" };
        env.deliver(kind === "picker" ? { action: "securePickerResult", token: "one", payload: result }
            : { action: "credentialPromptResult", token: "one", result });
        env.callbacks[0].callback({ success: true, token: "one" });
        // Expire unresolved requests so a dropped result fails without hanging.
        for (const timer of [...env.timers]) timer();
        assert.deepEqual(await pending, result);
        assert.equal(env.timers.size, 0);
    } finally { env.cleanup(); }
});

test("delivery tokens isolate concurrent openings and dispose resolves callbacks still in flight", async () => {
    const env = environment();
    try {
        const first = env.bridge.openSecurePicker("identity");
        const second = env.bridge.openSecurePicker("login");
        env.deliver({ action: "securePickerResult", token: "two", payload: { id: 2 } });
        env.callbacks[0].callback({ success: true, token: "one" });
        env.callbacks[1].callback({ success: true, token: "two" });
        assert.deepEqual(await second, { id: 2 });
        env.deliver({ action: "securePickerResult", token: "one", payload: { id: 1 } });
        assert.deepEqual(await first, { id: 1 });
        const third = env.bridge.openSecurePicker("identity");
        const prompt = env.bridge.openCredentialPrompt("alice", "synthetic");
        env.bridge.dispose();
        assert.equal(await third, null);
        assert.deepEqual(await prompt, { action: "cancel" });
        env.callbacks[2].callback({ success: true, token: "late" });
        assert.equal(env.timers.size, 0);
    } finally { env.cleanup(); }
});

test("normal results, cancellation, timeouts and opening errors all clean up", async () => {
    const env = environment();
    try {
        const pending = env.bridge.openCredentialPrompt("alice", "synthetic");
        env.callbacks[0].callback({ success: true, token: "one" });
        env.deliver({ action: "credentialPromptResult", token: "one", result: { action: "update" } });
        assert.deepEqual(await pending, { action: "update" });
        const cancelled = env.bridge.openSecurePicker("identity");
        env.deliver({ action: "securePickerResult", token: "two", payload: null });
        env.callbacks[1].callback({ success: true, token: "two" });
        assert.equal(await cancelled, null);
        const expired = env.bridge.openSecurePicker("identity");
        env.callbacks[2].callback({ success: true, token: "three" });
        for (const timer of [...env.timers]) timer();
        assert.equal(await expired, null);
        const failed = env.bridge.openSecurePicker("identity");
        env.callbacks[3].callback({ success: false, error: "Locked" });
        await assert.rejects(failed, /Locked/);
        const skipped = env.bridge.openCredentialPrompt("alice", "synthetic");
        env.callbacks[4].callback({ skipped: true });
        assert.deepEqual(await skipped, { action: "skipped" });
        assert.equal(env.timers.size, 0);
    } finally { env.cleanup(); }
});
