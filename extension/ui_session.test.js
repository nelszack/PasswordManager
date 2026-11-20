const test = require("node:test");
const assert = require("node:assert/strict");
const { loadScript } = require("./test_harness.cjs");

function session({ connectThrows = false } = {}) {
    const ports = [];
    const dispatched = [];
    const timers = new Map();
    let nextTimer = 0;
    let pagehide;
    const context = {
        Event: class {
            constructor(type) {
                this.type = type;
            }
        },
        setTimeout(callback, delay) {
            const id = ++nextTimer;
            timers.set(id, { callback, delay });
            return id;
        },
        clearTimeout: id => timers.delete(id),
        window: {
            dispatchEvent: event => dispatched.push(event.type),
            addEventListener(type, listener, options) {
                assert.equal(type, "pagehide");
                assert.deepEqual({ ...options }, { once: true });
                pagehide = listener;
            },
        },
        chrome: {
            runtime: {
                connect({ name }) {
                    if (connectThrows) throw new Error("Extension context invalidated.");
                    const port = {
                        name,
                        disconnected: false,
                        listener: null,
                        onDisconnect: { addListener: listener => (port.listener = listener) },
                        disconnect() {
                            port.disconnected = true;
                        },
                    };
                    ports.push(port);
                    return port;
                },
            },
        },
    };
    loadScript("ui_session.js", context);
    return { ports, dispatched, timers, pagehide: () => pagehide() };
}

test("extension views hold a live-status lease and reconnect after a worker restart", () => {
    const env = session();
    assert.equal(env.ports.length, 1);
    assert.equal(env.ports[0].name, "pm-ui");
    env.ports[0].listener();
    assert.deepEqual(env.dispatched, ["pm-worker-disconnected"]);
    const [[id, { callback, delay }]] = env.timers.entries();
    assert.equal(delay, 250);
    env.timers.delete(id);
    callback();
    assert.equal(env.ports.length, 2, "reconnecting wakes the restarted worker");
    env.pagehide();
    assert.equal(env.ports[1].disconnected, true);
    env.ports[1].listener();
    assert.equal(env.timers.size, 0, "a closing view does not reconnect");
});

test("a view whose extension context is gone reports the disconnection", () => {
    const env = session({ connectThrows: true });
    assert.equal(env.ports.length, 0);
    assert.deepEqual(env.dispatched, ["pm-worker-disconnected"]);
    env.pagehide();
});
