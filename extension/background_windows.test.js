const test = require("node:test");
const assert = require("node:assert/strict");
const windows = require("./background_windows.js");

function environment(result) {
    const created = [],
        removed = [],
        timers = [];
    const chrome = {
        runtime: { lastError: null, getURL: path => `chrome-extension://id/${path}` },
        windows: {
            create(options, callback) {
                created.push(options);
                chrome.runtime.lastError = result.error ? { message: result.error } : null;
                callback(result.window);
                chrome.runtime.lastError = null;
            },
            remove(id, callback) {
                removed.push(id);
                callback();
            },
        },
    };
    const service = windows.create({
        chrome,
        page: "picker.html",
        width: 380,
        height: 480,
        setTimeout: (callback, delay) => timers.push({ callback, delay }),
        unavailable: "Could not open secure picker",
    });
    return { service, created, removed, timers };
}

test("decision windows register the token's window and its expiry", async () => {
    const env = environment({ window: { id: 42 } });
    let expired = 0;
    const id = await env.service.open("to ken", "value", {
        isCurrent: () => true,
        expiresAt: Date.now() + 60_000,
        onExpire: () => expired++,
    });
    assert.equal(id, 42);
    assert.deepEqual(env.created, [
        {
            url: "chrome-extension://id/picker.html?token=to%20ken",
            type: "popup",
            width: 380,
            height: 480,
            focused: true,
        },
    ]);
    assert.equal(env.timers.length, 1);
    assert.ok(env.timers[0].delay > 59_000 && env.timers[0].delay <= 60_000);
    env.timers[0].callback();
    assert.equal(expired, 1);
    assert.equal(env.service.has(42), true);
    assert.equal(env.service.release(42), "value");
    assert.equal(env.service.release(42), undefined);
    env.service.close(42);
    env.service.close(null);
    assert.deepEqual(env.removed, [42]);
});

test("a decision that ends while its window opens closes that window", async () => {
    const env = environment({ window: { id: 7 } });
    assert.equal(await env.service.open("token", "value", { isCurrent: () => false }), null);
    assert.deepEqual(env.removed, [7]);
    assert.equal(env.service.has(7), false);
    assert.equal(env.timers.length, 0);
});

test("window creation failures reject with the browser's or the caller's message", async () => {
    await assert.rejects(
        environment({ error: "Too many windows" }).service.open("t", "v", { isCurrent: () => true }),
        /Too many windows/
    );
    await assert.rejects(
        environment({ window: {} }).service.open("t", "v", { isCurrent: () => true }),
        /Could not open secure picker/
    );
});
