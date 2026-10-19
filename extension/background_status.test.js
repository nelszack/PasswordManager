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
