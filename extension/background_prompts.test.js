const test = require("node:test");
const assert = require("node:assert/strict");
const prompts = require("./background_prompts.js");
const security = require("./background_security.js");
const promptState = require("./credential_prompt_state.js");

function environment() {
    const calls = [], deliveries = [], removed = [], timers = [];
    let saveError, lookupError, windowError, remembered, held, resolveSave, matched = false;
    let holdLookup, resolveLookup, holdMatch, resolveMatch, holdWindow, createWindow;
    const chrome = { runtime: { id: "abcdefghijklmnopabcdefghijklmnop", getURL: path => `chrome-extension://abcdefghijklmnopabcdefghijklmnop/${path}` },
        tabs: { sendMessage(tab, message, options, callback) { deliveries.push(message); callback(); } },
        windows: { create(options, callback) {
            if (holdWindow) { createWindow = () => callback({ id: 42 }); return; }
            if (windowError) { chrome.runtime.lastError = { message: windowError }; callback(); delete chrome.runtime.lastError; }
            else callback({ id: 42 });
        }, remove(id, callback) { removed.push(id); callback(); } }
    };
    const service = prompts.create({ chrome, security, promptState,
        pendingCredentials: { takeRemembered() { const value = remembered; remembered = null; return value; } },
        matchesFilledLogin: async () => holdMatch ? new Promise(resolve => { resolveMatch = resolve; }) : matched,
        refreshStatus() {}, crypto: require("node:crypto").webcrypto,
        setTimeout(fn) { timers.push(fn); }, onLoginContext() {},
        async nativeRequest(action, fields) {
            calls.push({ action, fields });
            if (action === "getLoginItems") {
                if (lookupError) throw new Error(lookupError);
                if (holdLookup) await new Promise(resolve => { resolveLookup = resolve; });
                return { success: true, sessionId: "a".repeat(64), data: [{"revision": 1, "id": 7, "name": "Example", "username": "alice"}] };
            }
            if (held) return new Promise(resolve => { resolveSave = resolve; });
            if (saveError) throw saveError;
            return { success: true, data: "Saved" };
        }
    });
    const sender = { tab: { id: 1 }, frameId: 0, url: "https://example.com/login" };
    const popup = { id: chrome.runtime.id, url: chrome.runtime.getURL("credential_prompt.html") };
    const open = (request = {}) => service.open({ username: "alice", password: "synthetic", ...request }, sender);
    const complete = (token, action = "add") => service.complete({ token, selection: { action, name: "Example" } }, popup);
    return { service, sender, popup, calls, deliveries, removed, timers, open, complete,
        failSave(error) { saveError = error; }, failLookup(error) { lookupError = error; },
        failWindow(error) { windowError = error; }, remember(record) { remembered = record; }, match() { matched = true; },
        hold() { held = true; }, release(response) { resolveSave(response); },
        holdLookup() { holdLookup = true; }, releaseLookup() { resolveLookup(); },
        holdMatch() { holdMatch = true; }, releaseMatch() { resolveMatch(false); },
        holdWindow() { holdWindow = true; }, releaseWindow() { createWindow(); }
    };
}

test("uncertain saves block retries, retain an error and allow explicit cancellation", async () => {
    const env = environment(); const { token } = await env.open();
    env.failSave(Object.assign(new Error("Save may still complete; review the vault"), { uncertain: true }));
    await assert.rejects(env.complete(token), error => error.uncertain === true);
    assert.match(env.service.data({ token }, env.popup).error, /may still complete/);
    await assert.rejects(env.complete(token), /review the vault/);
    assert.equal(env.calls.filter(call => call.action === "saveCredentials").length, 1);
    assert.equal((await env.complete(token, "cancel")).success, true);
    assert.equal(env.service.data({ token }, env.popup).success, false);
    assert.equal(env.deliveries.at(-1).result.action, "cancel");
});

test("invalidation while opening a save prompt cancels lookup, comparison, and window creation", async t => {
    for (const stage of ["Lookup", "Match", "Window"]) {
        await t.test(stage, async () => {
            const env = environment(); env[`hold${stage}`]();
            const opening = env.open();
            await new Promise(resolve => setImmediate(resolve));
            env.service.invalidate(); env[`release${stage}`]();
            assert.equal((await opening).skipped, true);
            assert.equal(env.timers.length, 0);
            assert.deepEqual(env.removed, stage === "Window" ? [42] : []);
        });
    }
});

test("a failed save cannot revive a prompt invalidated while the write was pending", async () => {
    const env = environment(); const { token } = await env.open(); env.hold();
    const saving = env.complete(token);
    const rejected = assert.rejects(saving, /Vault locked/);
    env.service.invalidate();
    env.release({ success: false, error: "Vault locked" }); await rejected;
    assert.equal(env.service.data({ token }, env.popup).success, false);
    await assert.rejects(env.complete(token), /expired/);
    assert.equal(env.calls.filter(call => call.action === "saveCredentials").length, 1);
});

test("native transport uncertainty and a definite validation error have different retry behavior", async () => {
    const env = environment(); const { token } = await env.open(); env.hold();
    const completion = env.complete(token);
    const rejected = assert.rejects(completion, error => error.uncertain === true);
    env.release({ success: false, error: "Response lost", uncertain: true }); await rejected;
    await assert.rejects(env.complete(token), /Response lost/);
    const definite = environment(); const opened = await definite.open();
    definite.failSave(new Error("Name already exists"));
    await assert.rejects(definite.complete(opened.token), /already exists/);
    definite.failSave(null);
    assert.equal((await definite.complete(opened.token, "update")).success, true);
});

test("duplicate decisions cannot save twice and a closing window cannot cancel an accepted save", async () => {
    const env = environment(); const { token } = await env.open(); env.hold();
    const completion = env.complete(token);
    await assert.rejects(env.complete(token), /already in progress/);
    assert.equal(env.service.windowRemoved(42), true);
    assert.equal(env.service.windowRemoved(99), false);
    env.service.invalidate();
    env.release({ success: true, data: "Saved" }); await completion;
    assert.equal(env.calls.filter(call => call.action === "saveCredentials").length, 1);
    assert.equal(env.deliveries.at(-1).result.action, "add");
});

test("untrusted, expired and invalid prompts cannot write to the vault", async () => {
    const env = environment(); const { token } = await env.open();
    assert.equal(env.service.data({ token }, env.sender).success, false);
    await assert.rejects(env.service.complete({ token }, env.sender), /Invalid credential prompt sender/);
    env.timers[0]();
    await assert.rejects(env.complete(token), /expired/);
    assert.equal(env.service.data({ token }, env.popup).success, false);
    assert.deepEqual(env.removed, [42]);
    await assert.rejects(env.open({ password: "" }), /Invalid credential/);
    await assert.rejects(env.open({ password: "bad\nsecret" }), /Invalid credential/);
});

test("lookup failures, matched credentials and failed windows leave no prompt behind", async () => {
    const unavailable = environment(); unavailable.failLookup("Disconnected");
    assert.equal((await unavailable.open()).skipped, true);
    const matched = environment(); matched.match();
    assert.equal((await matched.open()).skipped, true);
    const failed = environment(); failed.failWindow("Window unavailable");
    await assert.rejects(failed.open(), /Window unavailable/);
    assert.equal(failed.deliveries.length, 0);
});

test("only a current same-origin remembered username is used across navigation", async () => {
    const env = environment(); env.remember({ domain: "https://example.com", time: Date.now(), username: "alice" });
    const { token } = await env.open({ username: "" });
    assert.equal(env.service.data({ token }, env.popup).data.username, "alice");
    env.service.windowRemoved(42);
    assert.equal(env.deliveries.at(-1).result.action, "cancel");
    const stale = environment(); stale.remember({ domain: "https://example.com", time: Date.now() - 60001, username: "alice" });
    const opened = await stale.open({ username: "" });
    assert.equal(stale.service.data({ token: opened.token }, stale.popup).data.askForUsername, true);
});

test("save and update prompts send the session captured by their lookup", async () => {
    for (const action of ["add", "update"]) {
        const env = environment(); const { token } = await env.open();
        await env.complete(token, action);
        const write = env.calls.at(-1);
        assert.equal(write.fields.expectedSession, "a".repeat(64));
        if (action === "update") assert.equal(write.fields.expectedRevision, 1);
    }
});
