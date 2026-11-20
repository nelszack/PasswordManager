const test = require("node:test");
const assert = require("node:assert/strict");
const { loadScript } = require("./test_harness.cjs");

function entry({ available = true } = {}) {
    const listeners = {};
    const events = [];
    const state = { available, controllers: [] };
    const content = {
        runtimeAvailable: () => state.available,
        create() {
            const id = state.controllers.length + 1;
            const controller = {
                id,
                started: false,
                start() {
                    controller.started = true;
                    events.push(`start ${id}`);
                    return id === 3 ? Promise.reject(new Error("restore failed")) : Promise.resolve();
                },
                handlePageHide(event) {
                    events.push(`capture ${id} ${event.isTrusted}`);
                    if (event.fail) throw new Error("capture failed");
                },
                dispose() {
                    events.push(`dispose ${id}`);
                },
            };
            state.controllers.push(controller);
            return controller;
        },
    };
    const logged = [];
    const context = {
        require: name => {
            assert.equal(name, "./content.js");
            return content;
        },
        console: { log: (...args) => logged.push(args) },
        window: {
            addEventListener(type, listener) {
                assert.equal(listeners[type], undefined, `one ${type} listener`);
                listeners[type] = listener;
            },
        },
    };
    loadScript("content_entry.js", context);
    return { listeners, events, state, logged };
}

test("page hide captures credentials before disposal in a single listener", () => {
    const env = entry();
    assert.deepEqual(env.events, ["start 1"]);
    env.listeners.pagehide({ isTrusted: true });
    assert.deepEqual(env.events, ["start 1", "capture 1 true", "dispose 1"]);
    env.listeners.pagehide({ isTrusted: true });
    assert.equal(env.events.length, 3, "nothing remains to capture after disposal");
});

test("page scripts cannot dispose the controller with a synthetic page hide", () => {
    const env = entry();
    env.listeners.pagehide({ isTrusted: false });
    assert.deepEqual(env.events, ["start 1"]);
});

test("a failed capture still disposes, and back/forward restores mount a new controller", async () => {
    const env = entry();
    assert.throws(() => env.listeners.pagehide({ isTrusted: true, fail: true }), /capture failed/);
    assert.deepEqual(env.events, ["start 1", "capture 1 true", "dispose 1"]);
    env.listeners.pageshow({ persisted: false });
    assert.equal(env.state.controllers.length, 1);
    env.listeners.pageshow({ persisted: true });
    env.listeners.pageshow({ persisted: true });
    assert.deepEqual(env.events.slice(3), ["start 2", "dispose 2", "start 3"]);
    await new Promise(resolve => setImmediate(resolve));
    assert.match(String(env.logged[0][1]), /restore failed/);
});

test("scripts left behind by an extension update never mount", () => {
    const env = entry({ available: false });
    assert.deepEqual(env.events, []);
    env.listeners.pageshow({ persisted: true });
    env.listeners.pagehide({ isTrusted: true });
    assert.deepEqual(env.events, []);
});
