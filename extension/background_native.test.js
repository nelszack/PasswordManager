const test = require("node:test");
const assert = require("node:assert/strict");
const native = require("./background_native.js");
const protocol = require("./native_protocol.js");
const { nativeFields, nativeData } = require("./test_fixtures.cjs");

function environment(options = {}) {
    const ports = [], timers = new Map();
    let timerId = 0, invalidations = 0, connectError, postError;
    const chrome = { runtime: { connectNative() {
        if (connectError) throw new Error(connectError);
        const port = { requests: [],
            onMessage: { addListener(fn) { port.receive = fn; } },
            onDisconnect: { addListener(fn) { port.disconnect = fn; } },
            postMessage(request) { if (postError) throw new Error(postError); port.requests.push(request); }
        };
        ports.push(port); return port;
    } } };
    const bridge = native.create({ chrome, protocol, contract: require("./command_contract.js"), crypto: require("node:crypto").webcrypto, idleTimeoutMs: 0, ...options,
        onDisconnect() { invalidations++; },
        setTimeout(fn, ms) { timers.set(++timerId, { fn, ms }); return timerId; },
        clearTimeout(id) { timers.delete(id); }
    });
    const request = bridge.request;
    bridge.request = (action, fields = {}) => {
        const defaults = nativeFields(action);
        return request(action, { ...defaults, ...fields, ...(fields.item ? { item: { ...defaults.item, ...fields.item } } : {}) });
    };
    function answer(port, index = -1, extra = {}) {
        const request = port.requests.at(index);
        const data = nativeData(request.action);
        if (request.action === "operationStatus" && extra.data) extra = { ...extra, data: { revision: null, ...extra.data } };
        const response = { id: request.id, protocolVersion: 1, success: true, data, ...extra };
        if (request.operationId && response.success) response.operation = { operationId: request.operationId, state: "committed", revision: null };
        port.receive(response);
    }
    return { bridge, ports, timers, chrome, answer,
        expire(id) { const timer = timers.get(id); timers.delete(id); timer.fn(); },
        failConnect(message) { connectError = message; },
        failPost(message) { postError = message; },
        invalidations: () => invalidations
    };
}

test("lock and status have a control host independent of ordinary work and Duo", async () => {
    const env = environment();
    const save = env.bridge.request("managerUpdate", { item: { password: "synthetic" } });
    const duo = env.bridge.request("managerDuoRequests");
    assert.equal(env.timers.get(2).ms, 65_000);
    const lock = env.bridge.request("lock");
    assert.equal(env.timers.get(3).ms, 15000);
    assert.equal(env.ports.length, 3);
    env.answer(env.ports[2]); await lock;
    const status = env.bridge.request("status");
    env.answer(env.ports[2]); await status;
    assert.equal(env.ports.length, 3);
    env.answer(env.ports[0]); await save;
    env.answer(env.ports[1]); await duo;
    assert.equal(env.timers.size, 0);
});

test("a queued mutation expires without ever reaching the native host", async () => {
    const env = environment();
    const first = env.bridge.request("managerList");
    const queued = env.bridge.request("managerDelete", { entryId: 1 });
    const rejected = assert.rejects(queued, error => !error.uncertain && /before it was sent/.test(error.message));
    env.expire(2); await rejected;
    assert.equal(env.ports[0].requests.length, 1);
    env.answer(env.ports[0]); await first;
    assert.equal(env.ports[0].requests.length, 1);
    assert.equal(env.timers.size, 0);
});

test("a timed-out sent mutation stays ordered before review and never resolves from a late reply", async () => {
    const env = environment();
    const save = env.bridge.request("managerAdd");
    const rejected = assert.rejects(save, error => error.uncertain && /may still complete/.test(error.message));
    env.expire(1); await rejected;
    const review = env.bridge.request("managerList");
    assert.equal(env.ports[0].requests.length, 1);
    env.answer(env.ports[0], 0);
    assert.equal(env.ports[0].requests[1].action, "managerList");
    // A duplicate old reply cannot settle the review.
    env.answer(env.ports[0], 0);
    assert.equal(env.timers.size, 1);
    env.answer(env.ports[0], 1); await review;
    assert.equal(env.timers.size, 0);
});

test("disconnect isolates item and Duo hosts and distinguishes sent mutations from queued work", async t => {
    for (const action of ["saveCredentials", "managerDuoRequests"]) {
        await t.test(action, async () => {
            const env = environment();
            const invalidations = action === "saveCredentials" ? 1 : 0;
            const queuedAction = action === "managerDuoRequests" ? action : "managerList";
            const active = env.bridge.request(action);
            const read = env.bridge.request(queuedAction);
            const status = env.bridge.request("status");
            const sentRejected = assert.rejects(active, error => error.uncertain === (action === "saveCredentials") && /disconnected/.test(error.message));
            const queuedRejected = assert.rejects(read, error => error.uncertain === false);
            env.ports[0].disconnect();
            await Promise.all([sentRejected, queuedRejected]);
            env.answer(env.ports[1]); await status;
            assert.equal(env.invalidations(), invalidations);
            const reconnected = env.bridge.request(queuedAction);
            assert.equal(env.ports.length, 3);
            env.ports[0].disconnect();
            env.ports[0].receive({ id: env.ports[2].requests[0].id, success: true, data: "stale" });
            assert.equal(env.invalidations(), invalidations);
            env.answer(env.ports[2]); await reconnected;
            assert.equal(env.timers.size, 0);
        });
    }
});

test("malformed and cross-channel replies cannot confirm a mutation", async () => {
    const env = environment();
    const save = env.bridge.request("managerUpdate");
    const status = env.bridge.request("status");
    const rejected = assert.rejects(save, error => error.uncertain && /Invalid native/.test(error.message));
    env.ports[0].receive({ id: env.ports[1].requests[0].id, success: true, data: {} });
    assert.equal(env.timers.size, 2);
    env.answer(env.ports[0], 0, { success: "yes" }); await rejected;
    env.answer(env.ports[1]); await status;
});

test("a lost native reply reports uncertainty even before the browser deadline", async () => {
    const env = environment();
    const save = env.bridge.request("managerDelete");
    env.answer(env.ports[0], 0, { success: false, error: "Reply lost", uncertain: true });
    assert.equal((await save).uncertain, true);
    assert.equal(env.bridge.unresolved().length, 1);
});

test("read timeouts and failures before sending are safe to retry", async () => {
    const env = environment();
    const read = env.bridge.request("managerList");
    const rejected = assert.rejects(read, error => !error.uncertain && /timed out/.test(error.message));
    env.expire(1); await rejected;
    env.ports[0].disconnect();
    env.failConnect("Host not installed");
    await assert.rejects(env.bridge.request("managerAdd"), error => !error.uncertain && /not installed/.test(error.message));
    env.failConnect(null); env.failPost("Port closed");
    await assert.rejects(env.bridge.request("managerAdd"), error => !error.uncertain && /Port closed/.test(error.message));
    assert.equal(env.timers.size, 0);
});

test("native queues are bounded and request metadata cannot be overridden", async () => {
    const env = environment();
    const active = env.bridge.request("managerList", { id: 999, action: "managerDelete" });
    assert.equal(env.ports[0].requests[0].action, "managerList");
    assert.equal(env.ports[0].requests[0].id, 1);
    const queued = Array.from({ length: 32 }, () => env.bridge.request("managerList"));
    const rejections = queued.map(call => assert.rejects(call, /disconnected/));
    await assert.rejects(env.bridge.request("managerAdd"), /Too many/);
    const activeRejection = assert.rejects(active, /disconnected/);
    env.ports[0].disconnect();
    await Promise.all([activeRejection, ...rejections]);
    assert.equal(env.timers.size, 0);
});

test("a silent live host is disconnected at a bounded recovery deadline without replaying its mutation", async () => {
    const env = environment();
    const mutation = env.bridge.request("managerAdd", { item: { name: "Example" } });
    const rejected = assert.rejects(mutation, error => error.uncertain && typeof error.operationId === "string");
    const operationId = env.ports[0].requests[0].operationId;
    env.expire(1); await rejected;
    const queued = env.bridge.request("managerList");
    const queuedRejected = assert.rejects(queued, /recovery deadline/);
    env.expire(2); await queuedRejected;
    assert.equal(env.ports[0].requests.length, 1);
    assert.deepEqual(env.bridge.unresolved(), [{ operationId, action: "managerAdd" }]);
    const review = env.bridge.reconcile(operationId);
    env.answer(env.ports[1], 0, { data: { state: "pending", operationId } });
    await review;
    await assert.rejects(env.bridge.request("managerDelete", { entryId: 1 }), error => error.uncertain && error.operationId === operationId);
    const finished = env.bridge.reconcile(operationId);
    env.answer(env.ports[1], 1, { data: { state: "committed", operationId, revision: 1 } });
    await finished;
    const next = env.bridge.request("managerDelete", { entryId: 1 });
    assert.equal(env.ports.length, 3);
    env.answer(env.ports[2]); await next;
    assert.equal(env.bridge.unresolved().length, 0);
});

test("idle native connections close without invalidating current decisions and reopen on demand", async () => {
    const env = environment({ idleTimeoutMs: 20_000 });
    const read = env.bridge.request("managerList"); env.answer(env.ports[0]); await read;
    assert.equal(env.timers.get(2).ms, 20_000);
    env.expire(2);
    assert.equal(env.invalidations(), 0);
    const next = env.bridge.request("managerList");
    assert.equal(env.ports.length, 2); env.answer(env.ports[1]); await next;
});

test("worker restart retains only operation identities and requires reconciliation before another write", async () => {
    const stored = { pmUnresolvedOperations: [{ operationId: "save-before-crash", action: "managerAdd" }] };
    const session = {
        get(key, callback) { callback({ [key]: structuredClone(stored[key]) }); },
        set(value, callback) { Object.assign(stored, structuredClone(value)); callback(); }
    };
    const env = environment();
    // Instantiate a fresh bridge against browser-owned session storage.
    const bridge = native.create({ chrome: { ...env.chrome, storage: { session } }, protocol,
        contract: require("./command_contract.js"), crypto: require("node:crypto").webcrypto,
        onDisconnect() {}, setTimeout, clearTimeout, idleTimeoutMs: 0 });
    await assert.rejects(bridge.request("managerAdd", { item: { name: "Another" } }), /reconciled/);
    assert.equal(env.ports.length, 0);
    const review = bridge.reconcile("save-before-crash");
    const request = env.ports[0].requests[0];
    env.ports[0].receive({ id: request.id, protocolVersion: 1, success: true, data: { state: "failed", operationId: "save-before-crash", revision: null } });
    await review;
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(stored.pmUnresolvedOperations, []);
});

test("a committed HOTP result with a full-width counter returns its code without entering recovery", async () => {
    const env = environment();
    const code = env.bridge.request("getTotp", { entryId: 1 });
    env.answer(env.ports[0], 0, { data: { mode: "hotp", code: "123456", expires_in: null, counter: "18446744073709551614" } });
    const response = await code;
    assert.equal(response.data.counter, "18446744073709551614");
    assert.equal(response.data.code, "123456");
    assert.deepEqual(env.bridge.unresolved(), []);
});

test("unknown operation outcomes require an explicit acknowledgement and pending operations cannot be acknowledged", async () => {
    const env = environment();
    const mutation = env.bridge.request("managerAdd", { item: { name: "Example" } });
    const rejected = assert.rejects(mutation, error => error.uncertain);
    const operationId = env.ports[0].requests[0].operationId;
    env.expire(1); await rejected;
    assert.throws(() => env.bridge.acknowledgeUnknown(operationId), /reviewed unknown/);
    let review = env.bridge.reconcile(operationId);
    env.answer(env.ports[1], 0, { data: { state: "pending", operationId } }); await review;
    assert.throws(() => env.bridge.acknowledgeUnknown(operationId), /reviewed unknown/);
    review = env.bridge.reconcile(operationId);
    env.answer(env.ports[1], 1, { data: { state: "unknown", operationId } }); await review;
    assert.equal(env.bridge.acknowledgeUnknown(operationId).success, true);
    assert.equal(env.bridge.unresolved().length, 0);
    assert.equal(env.ports[0].requests.length, 1, "acknowledgement does not replay the original mutation");
});
