const test = require("node:test");
const assert = require("node:assert/strict");
const native = require("./background_native.js");
const protocol = require("./native_protocol.js");

function environment() {
    const ports = [], timers = [];
    const bridge = native.create({ chrome: { runtime: { connectNative: () => {
        const port = { requests: [], onMessage: { addListener: listener => { port.receive = listener; } }, onDisconnect: { addListener: listener => { port.disconnect = listener; } }, postMessage: request => port.requests.push(request) };
        ports.push(port); return port;
    } } }, protocol, onDisconnect() {}, setTimeout: (callback, ms) => { timers.push({ callback, ms }); return timers.length; }, clearTimeout() {} });
    const answer = (port, index = -1) => port.receive({ id: port.requests.at(index).id, success: true, data: {} });
    return { bridge, ports, timers, answer };
}
test("Duo network requests cannot queue lock/status behind their native host", async () => {
    const { bridge, ports, timers, answer } = environment();
    const poll = bridge.request("managerDuoRequests", { entryId: 1 });
    assert.equal(timers.at(-1).ms, 60000);
    const lock = bridge.request("lockVault");
    assert.equal(timers.at(-1).ms, 7000);
    assert.equal(ports.length, 2);
    assert.equal(ports[0].requests[0].action, "managerDuoRequests");
    assert.equal(ports[1].requests[0].action, "lockVault");
    answer(ports[1]); await lock;
    const status = bridge.request("status");
    assert.equal(ports.length, 2); answer(ports[1]); await status;
    answer(ports[0]); await poll;
});
test("a failed Duo connection does not disconnect lock/status", async () => {
    const { bridge, ports, answer } = environment();
    const poll = bridge.request("managerDuoRequests");
    const rejected = assert.rejects(poll, /Duo native messaging host disconnected/);
    const status = bridge.request("status");
    ports[0].disconnect(); await rejected;
    answer(ports[1]); await status;
});
