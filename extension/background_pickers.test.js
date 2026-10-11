const test = require("node:test");
const assert = require("node:assert/strict");
const pickers = require("./background_pickers.js");
const security = require("./background_security.js");
const protocol = require("./native_protocol.js");
const flush = () => new Promise(resolve => setImmediate(resolve));

function environment() {
    const deliveries = [], removed = [], timers = [], calls = [], logins = [];
    let heldTab, releaseTab, heldWindow, releaseWindow, heldDelivery, releaseDelivery;
    let delivered;
    const delivery = new Promise(resolve => { delivered = resolve; });
    const chrome = {
        runtime: { id: "abcdefghijklmnopabcdefghijklmnop", getURL: path => `chrome-extension://abcdefghijklmnopabcdefghijklmnop/${path}` },
        tabs: {
            async get() { if (heldTab) await new Promise(resolve => { releaseTab = resolve; }); return { url: "https://example.com" }; },
            async sendMessage(tab, message, options) {
                deliveries.push({ tab, message, options });
                delivered();
                if (heldDelivery) await new Promise(resolve => { releaseDelivery = resolve; });
            }
        },
        windows: {
            create(options, callback) { if (heldWindow) releaseWindow = () => callback({ id: 42 }); else callback({ id: 42 }); },
            remove(id, callback) { removed.push(id); callback?.(); }
        }
    };
    const service = pickers.create({ chrome, security, protocol, crypto: require("node:crypto").webcrypto,
        setTimeout(fn) { timers.push(fn); },
        onLoginSelected(login) { logins.push(login); },
        async nativeRequest(action) {
            calls.push(action);
            return { success: true, data: action === "getLoginItem"
                ? '{"username":"alice","password":"synthetic-secret"}' : '[{"id":1,"name":"Example"}]' };
        }
    });
    const sender = { tab: { id: 1 }, frameId: 3, documentId: "original-document", url: "https://example.com" };
    const popup = { id: chrome.runtime.id, url: chrome.runtime.getURL("picker.html") };
    return { service, sender, popup, deliveries, removed, timers, calls, logins, delivery,
        open: () => service.open({ kind: "login" }, sender),
        holdTab() { heldTab = true; }, releaseTab() { releaseTab(); },
        holdWindow() { heldWindow = true; }, releaseWindow() { releaseWindow(); },
        holdDelivery() { heldDelivery = true; }, releaseDelivery() { releaseDelivery(); }
    };
}

test("invalidation while opening a picker cancels tab lookup and delayed window creation", async t => {
    for (const stage of ["Tab", "Window"]) {
        await t.test(stage, async () => {
            const env = environment(); env[`hold${stage}`]();
            const opening = env.open();
            const rejected = assert.rejects(opening, /expired/);
            await flush(); env.service.invalidate(); env[`release${stage}`](); await rejected;
            assert.equal(env.calls.length, 0);
            assert.equal(env.timers.length, 0);
            assert.deepEqual(env.removed, stage === "Window" ? [42] : []);
        });
    }
});

test("a delayed delivery acknowledgement cannot recreate login context after locking", { timeout: 5000 }, async () => {
    const env = environment(); const { token } = await env.open(); await flush();
    env.holdDelivery();
    const completion = env.service.complete({ token, id: 1 }, env.popup);
    await env.delivery;
    env.service.invalidate(); env.releaseDelivery();
    assert.equal((await completion).success, true);
    assert.equal(env.logins.length, 0);
    assert.equal(await env.service.matchesFilledLogin(env.sender, "alice", "synthetic-secret"), false);
});

test("closing, canceling, expiring and invalidating a picker cancel its original document once", async t => {
    for (const action of ["close", "cancel", "expire", "invalidate"]) {
        await t.test(action, async () => {
            const env = environment(); const { token } = await env.open(); await flush();
            if (action === "close") env.service.windowRemoved(42);
            if (action === "cancel") await env.service.complete({ token, cancel: true }, env.popup);
            if (action === "expire") env.timers[0]();
            if (action === "invalidate") env.service.invalidate();
            assert.equal(env.service.data({ token }, env.popup).success, false);
            assert.equal(env.deliveries.length, 1);
            assert.equal(env.deliveries[0].message.token, token);
            assert.equal(env.deliveries[0].message.payload, null);
            assert.equal(env.deliveries[0].options.documentId, "original-document");
            const removed = env.removed.length;
            env.service.windowRemoved(42); env.service.invalidate(); env.timers[0]();
            assert.equal(env.deliveries.length, 1);
            assert.equal(env.removed.length, removed);
        });
    }
});
