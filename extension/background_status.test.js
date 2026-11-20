const test = require("node:test");
const assert = require("node:assert/strict");
const status = require("./background_status.js");
const state = require("./background_state.js");

test("idle browsers use alarms; overlapping extension views share a live monitor and release it", async () => {
    let onConnect, onAlarm, refreshes = 0, closes = 0, cleanups = 0;
    const intervals = new Map();
    const event = capture => ({ addListener: capture || (() => {}) });
    const service = status.create({ chrome: {
        runtime: { onInstalled: event(), onStartup: event(), onConnect: event(fn => onConnect = fn), sendMessage() {} },
        alarms: { create() {}, onAlarm: event(fn => onAlarm = fn) },
        action: { setBadgeText() {}, setBadgeBackgroundColor() {}, setTitle() {} }, storage: { local: { set() {} } }
    }, nativeRequest: async () => { refreshes++; return { success: true, nativeVersion: "0.1.0", protocolVersion: 1, data: { locked: true, version: "0.1.0", warning: null } }; },
        state, version: "0.1.0", protocolVersion: 1, invalidate() {}, cleanupExpired() { cleanups++; }, closeIdle() { closes++; },
        setInterval(fn, ms) { assert.equal(ms, 2000); intervals.set(1, fn); return 1; }, clearInterval(id) { intervals.delete(id); }
    });
    service.start(); await service.refresh();
    assert.equal(intervals.size, 0);
    const port = () => { let disconnect; return { name: "pm-ui", onDisconnect: event(fn => disconnect = fn), close() { disconnect(); } }; };
    const first = port(), second = port(); onConnect(first); onConnect(second);
    assert.equal(intervals.size, 1);
    first.close(); assert.equal(intervals.size, 1);
    second.close(); assert.equal(intervals.size, 0); assert.equal(closes, 1);
    onAlarm({ name: "status-poll" }); await service.refresh();
    assert.equal(cleanups, 1); assert.ok(refreshes >= 2);
});

test("an unlocked-to-unlocked session change invalidates old decisions and publishes new status", async () => {
    let sessionId = "a".repeat(64), invalidations = 0;
    const messages = [];
    const event = { addListener() {} };
    const service = status.create({ chrome: {
        runtime: { onInstalled: event, onStartup: event, onConnect: event, sendMessage(message) { messages.push(message); } },
        alarms: { create() {}, onAlarm: event },
        action: { setBadgeText() {}, setBadgeBackgroundColor() {}, setTitle() {} }, storage: { local: { set() {} } }
    }, nativeRequest: async () => ({ success: true, sessionId, nativeVersion: "0.1.0", protocolVersion: 2, data: { locked: false, version: "0.1.0", warning: null } }),
        state, version: "0.1.0", protocolVersion: 2, invalidate() { invalidations++; }, cleanupExpired() {}, setInterval() {} });
    await service.refresh();
    assert.equal(invalidations, 0);
    sessionId = "b".repeat(64);
    await service.refresh();
    assert.equal(invalidations, 1);
    assert.equal(messages.at(-1).status.sessionId, sessionId);
    assert.equal(messages.length, 2);
});

function statusService({ alarm = null, responses, now = () => 0 } = {}) {
    const calls = { invalidations: 0, badges: 0, alarmsCreated: [], messages: [], requests: 0 };
    const event = { addListener() {} };
    let index = 0;
    const service = status.create({
        chrome: {
            runtime: {
                onInstalled: event,
                onStartup: event,
                onConnect: event,
                sendMessage(message) {
                    calls.messages.push(message);
                },
            },
            alarms: {
                get(name, callback) {
                    assert.equal(name, "status-poll");
                    callback(alarm);
                },
                create(name, options) {
                    calls.alarmsCreated.push([name, options]);
                },
                onAlarm: event,
            },
            action: {
                setBadgeText() {
                    calls.badges++;
                },
                setBadgeBackgroundColor() {},
                setTitle() {},
            },
            storage: { local: { set() {} } },
        },
        nativeRequest: async () => {
            calls.requests++;
            return responses[Math.min(index++, responses.length - 1)];
        },
        state,
        version: "0.1.0",
        protocolVersion: 2,
        invalidate() {
            calls.invalidations++;
        },
        cleanupExpired() {},
        setInterval() {},
        now,
    });
    return { service, calls };
}
const statusResponse = (locked, sessionId = locked ? null : "a".repeat(64)) => ({
    success: true,
    sessionId,
    nativeVersion: "0.1.0",
    protocolVersion: 2,
    data: { locked, version: "0.1.0", warning: null },
});

test("decisions are invalidated only when the vault becomes unavailable, not on every locked refresh", async () => {
    const { service, calls } = statusService({
        responses: [
            statusResponse(true),
            statusResponse(true),
            statusResponse(true),
            statusResponse(false),
            statusResponse(false),
            statusResponse(true),
            statusResponse(true),
            { success: false, error: "Server not running" },
        ],
    });
    await service.refresh();
    assert.equal(calls.invalidations, 1, "a worker that starts locked clears anything it inherited");
    await service.refresh();
    await service.refresh();
    assert.equal(calls.invalidations, 1, "repeated locked refreshes leave an open picker's unlock guidance visible");
    await service.refresh();
    await service.refresh();
    assert.equal(calls.invalidations, 1, "unlocking does not invalidate");
    await service.refresh();
    assert.equal(calls.invalidations, 2, "locking invalidates");
    await service.refresh();
    await service.refresh();
    assert.equal(calls.invalidations, 2, "locked to not-running stays unavailable");
});

test("badge updates and status broadcasts happen only when status changes", async () => {
    const { service, calls } = statusService({
        responses: [statusResponse(false), statusResponse(false), statusResponse(true)],
    });
    await service.refresh();
    await service.refresh();
    assert.equal(calls.badges, 1);
    assert.equal(calls.messages.length, 1);
    await service.refresh();
    assert.equal(calls.badges, 2);
    assert.equal(calls.messages.length, 2);
});

test("worker restarts keep an existing status alarm instead of restarting its period", () => {
    const existing = statusService({ alarm: { name: "status-poll", periodInMinutes: 1 }, responses: [statusResponse(true)] });
    existing.service.start();
    assert.deepEqual(existing.calls.alarmsCreated, []);
    for (const alarm of [null, undefined, { name: "status-poll", periodInMinutes: 5 }]) {
        const missing = statusService({ alarm, responses: [statusResponse(true)] });
        missing.service.start();
        assert.deepEqual(missing.calls.alarmsCreated, [["status-poll", { periodInMinutes: 1 }]]);
    }
});

test("recent status reuses a fresh result and refreshes a stale one", async () => {
    let time = 1000;
    const { service, calls } = statusService({ responses: [statusResponse(false)], now: () => time });
    const first = await service.recent(10_000);
    assert.equal(calls.requests, 1);
    time += 9_999;
    assert.equal(await service.recent(10_000), first);
    assert.equal(calls.requests, 1);
    time += 1;
    await service.recent(10_000);
    assert.equal(calls.requests, 2);
});
