const test = require("node:test");
const assert = require("node:assert/strict");
const { loadScript } = require("./test_harness.cjs");

test("Duo polls cache unchanged text while authorization always checks live content", () => {
    let reads = 0, text = "Ordinary page", dirty, listener, disconnected = false;
    const timers = new Map(), events = {};
    let nextTimer = 0;
    const document = {
        visibilityState: "visible",
        body: { get innerText() { reads++; return text; } },
        addEventListener(name, handler) { events[name] = handler; },
        removeEventListener() {}
    };
    const context = {
        module: { exports: {} }, require: () => require("./duo_detection.js"), document,
        location: { href: "https://example.com/" },
        MutationObserver: class {
            constructor(handler) { dirty = handler; }
            observe() {} takeRecords() { return []; }
            disconnect() { disconnected = true; }
        },
        setTimeout(handler) { const id = ++nextTimer; timers.set(id, handler); return id; },
        clearTimeout(id) { timers.delete(id); },
        chrome: { runtime: {
            onMessage: { addListener(handler) { listener = handler; }, removeListener() {} },
            sendMessage(_message, callback) { callback(); }
        } },
        window: { addEventListener() {}, removeEventListener() {} }
    };
    loadScript("content_duo.js", context);
    const controller = context.module.exports.create();
    const tick = () => { const [id, handler] = timers.entries().next().value; timers.delete(id); handler(); };
    assert.equal(reads, 1);
    tick(); tick();
    assert.equal(reads, 1, "unchanged ordinary pages avoid repeated rendered-text reads");
    text = "Duo Push: Check your phone";
    dirty(); dirty(); dirty(); tick();
    assert.equal(reads, 2, "mutation bursts coalesce into one scan");
    let result;
    text = "Ordinary page";
    listener({ action: "getDuoChallengeState" }, {}, response => { result = response; });
    assert.equal(result.active, false, "authorization does not reuse a cached challenge");
    assert.equal(reads, 3);
    document.visibilityState = "hidden"; events.visibilitychange();
    assert.equal(reads, 3);
    document.visibilityState = "visible"; events.visibilitychange();
    assert.equal(reads, 4);
    controller.dispose();
    assert.equal(disconnected, true);
    assert.equal(timers.size, 0);
});
