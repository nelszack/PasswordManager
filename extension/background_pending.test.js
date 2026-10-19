const test = require("node:test");
const assert = require("node:assert/strict");
const pending = require("./background_pending.js");
const records = require("./pending_credentials.js");
const security = require("./background_security.js");

function environment() {
    let now = 1000, failure, closed;
    const stored = {}, timers = [];
    const chrome = { runtime: {}, tabs: { onRemoved: { addListener(fn) { closed = fn; } } }, storage: { session: {} } };
    for (const method of ["get", "set", "remove"]) {
        chrome.storage.session[method] = (value, callback) => queueMicrotask(() => {
            if (failure === method) {
                chrome.runtime.lastError = { message: `${method} failed` };
                callback(); delete chrome.runtime.lastError; return;
            }
            if (method === "get") callback(structuredClone(value === null ? stored : { [value]: stored[value] }));
            if (method === "set") { Object.assign(stored, structuredClone(value)); callback(); }
            if (method === "remove") { delete stored[value]; callback(); }
        });
    }
    const create = () => pending.create({ chrome, security,
        records: { MAX_AGE_MS: records.MAX_AGE_MS,
            create: (value, domain) => records.create(value, domain, now),
            usable: (record, domain) => records.usable(record, domain, now)
        }, setTimeout(fn) { timers.push(fn); }
    });
    const sender = { tab: { id: 7 }, frameId: 0, url: "https://example.com/login" };
    const call = (service, method, ...args) => new Promise(resolve => service[method](...args, resolve));
    const set = (service, value = "alice") => call(service, "set", { pending: { username: value } }, sender);
    return { create, stored, sender, timers, call, set,
        advance(ms) { now += ms; }, fail(method) { failure = method; }, closeTab(id) { closed(id); }
    };
}
const flush = () => new Promise(resolve => setImmediate(resolve));

test("pending usernames survive worker restart and are consumed exactly once", async () => {
    const env = environment(), first = env.create();
    assert.equal((await env.set(first)).success, true);
    const restarted = env.create();
    const [one, two] = await Promise.all([
        env.call(restarted, "consume", env.sender), env.call(restarted, "consume", env.sender)
    ]);
    assert.equal(one.pending.username, "alice");
    assert.equal(two.pending, null);
    assert.equal(env.stored["pmPopupPending:7"], undefined);
});

test("cross-origin and cross-tab navigation cannot consume another site's credentials", async () => {
    const env = environment(), service = env.create(); await env.set(service);
    const otherTab = await env.call(service, "consume", { ...env.sender, tab: { id: 8 } });
    assert.equal(otherTab.pending, null);
    const otherSite = await env.call(service, "consume", { ...env.sender, url: "https://attacker.example" });
    assert.equal(otherSite.pending, null);
    assert.equal((await env.call(service, "consume", env.sender)).pending, null);
});

test("expiry removes stored usernames without deleting a newer navigation record", async () => {
    const env = environment(), service = env.create(); await env.set(service, "old");
    env.advance(50000); await env.set(service, "replacement");
    env.advance(10000); env.timers[0](); await flush();
    assert.equal(env.stored["pmPopupPending:7"].username, "replacement");
    env.advance(50000); env.timers[1](); await flush();
    assert.equal(env.stored["pmPopupPending:7"], undefined);
    assert.equal(service.takeRemembered(env.sender), null);
});

test("cleanup after a worker restart removes expired and malformed session records", async () => {
    const env = environment(), service = env.create(); await env.set(service);
    env.stored.otherSetting = "preserved";
    env.stored["pmPopupPending:8"] = { domain: "https://example.com", password: "synthetic", time: "invalid" };
    env.advance(60000);
    await env.create().cleanup();
    assert.deepEqual(env.stored, { otherSetting: "preserved" });
});

test("closing a tab and clearing pending state remove both memory and storage", async () => {
    const env = environment(), service = env.create(); await env.set(service);
    env.closeTab(7); await flush();
    assert.equal(service.takeRemembered(env.sender), null);
    await env.set(service);
    assert.equal((await env.call(service, "clear", env.sender)).success, true);
    assert.equal((await env.call(service, "consume", env.sender)).pending, null);
});

test("remembered usernames are origin-bound and are not reusable", async () => {
    const env = environment(), service = env.create(); await env.set(service);
    assert.equal(service.takeRemembered(env.sender).username, "alice");
    assert.equal(service.takeRemembered(env.sender), null); await flush();
    assert.equal(env.stored["pmPopupPending:7"], undefined);
    await env.set(service);
    assert.equal(service.takeRemembered({ ...env.sender, url: "https://other.example" }), null);
});

test("storage failures disclose no pending secret and do not poison later operations", async () => {
    const env = environment(), service = env.create(); env.fail("set");
    assert.deepEqual(await env.set(service), { success: false, error: "set failed" });
    env.fail(null); await env.set(service);
    for (const method of ["get", "remove"]) {
        env.fail(method);
        assert.deepEqual(await env.call(service, "consume", env.sender), { success: false, error: `${method} failed` });
    }
    env.fail(null);
    assert.equal((await env.call(service, "consume", env.sender)).pending.username, "alice");
});

test("invalid senders and oversized pending payloads fail before storage", async () => {
    const env = environment(), service = env.create();
    const request = { pending: { username: "alice" } };
    for (const sender of [{}, { tab: { id: 7 }, url: "file:///tmp/test" }]) {
        assert.equal((await env.call(service, "set", request, sender)).success, false);
        assert.equal((await env.call(service, "consume", sender)).success, false);
    }
    assert.equal((await env.call(service, "clear", {})).success, false);
    assert.equal((await env.set(service, "x".repeat(4097))).success, false);
    assert.equal((await env.call(service, "set", {}, env.sender)).success, false);
    assert.deepEqual(env.stored, {});
});

test("navigation records reject password-bearing payloads and persist only username context", async () => {
    const env = environment(), service = env.create();
    const response = await env.call(service, "set", { pending: { username: "alice", password: "secret" } }, env.sender);
    assert.equal(response.success, false); assert.deepEqual(env.stored, {});
    await env.set(service);
    assert.deepEqual(env.stored["pmPopupPending:7"], { domain: "https://example.com", username: "alice", time: 1000 });
});
