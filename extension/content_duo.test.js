const test = require("node:test");
const assert = require("node:assert/strict");
const { loadScript } = require("./test_harness.cjs");

function environment({ text = "Ordinary page", href = "https://example.com/", top = true } = {}) {
    const state = { text, innerReads: 0, textReads: 0, sent: 0, flushes: 0, listener: null, removed: false };
    const timers = new Map(),
        events = {};
    let nextTimer = 0;
    const document = {
        visibilityState: "visible",
        body: {
            get innerText() {
                state.innerReads++;
                return state.text;
            },
            get textContent() {
                state.textReads++;
                return state.text;
            },
        },
        addEventListener(name, handler) {
            events[name] = handler;
        },
        removeEventListener(name) {
            delete events[name];
        },
    };
    const window = {};
    window.top = top ? window : {};
    const context = {
        module: { exports: {} },
        require: () => require("./duo_detection.js"),
        document,
        window,
        location: { href },
        setTimeout(handler, delay) {
            const id = ++nextTimer;
            timers.set(id, { handler, delay });
            return id;
        },
        clearTimeout(id) {
            timers.delete(id);
        },
        Date,
        chrome: {
            runtime: {
                onMessage: {
                    addListener(handler) {
                        state.listener = handler;
                    },
                    removeListener() {
                        state.removed = true;
                    },
                },
                sendMessage(message, callback) {
                    assert.equal(message.action, "observeDuoChallenge");
                    state.sent++;
                    callback();
                },
            },
        },
    };
    loadScript("content_duo.js", context);
    return {
        state,
        timers,
        events,
        document,
        context,
        create: options => context.module.exports.create({ flushMutations: () => state.flushes++, ...options }),
        tick() {
            const [id, { handler }] = timers.entries().next().value;
            timers.delete(id);
            handler();
        },
        ask() {
            let result;
            state.listener({ action: "getDuoChallengeState" }, {}, response => (result = response));
            return result;
        },
    };
}

test("Duo polls cache unchanged text while authorization always checks live content", () => {
    const env = environment();
    const duo = env.create();
    assert.equal(duo.enabled, true);
    assert.equal(env.state.textReads, 1);
    assert.equal(env.state.innerReads, 0, "pages that never mention Duo skip the rendered-text read");
    env.tick();
    env.tick();
    assert.equal(env.state.textReads, 1, "unchanged ordinary pages avoid repeated reads");
    assert.equal(env.state.flushes, 3, "each read first takes queued mutation records");
    env.state.text = "Duo Push: Check your phone";
    duo.mutated();
    duo.mutated();
    duo.mutated();
    env.tick();
    assert.equal(env.state.innerReads, 1, "mutation bursts coalesce into one scan");
    assert.equal(env.state.sent, 1);
    env.state.text = "Ordinary page";
    assert.equal(env.ask().active, false, "authorization does not reuse a cached challenge");
    duo.dispose();
    assert.equal(env.state.removed, true);
    assert.equal(env.timers.size, 0);
    assert.equal(env.events.visibilitychange, undefined);
});

test("hidden pages stop polling until they become visible again", () => {
    const env = environment({ text: "Duo Push: Check your phone" });
    env.create();
    assert.equal(env.state.sent, 1);
    assert.equal(env.timers.size, 1);
    env.document.visibilityState = "hidden";
    env.events.visibilitychange();
    assert.equal(env.timers.size, 0, "no timer runs while hidden");
    assert.equal(env.ask().active, false);
    const reads = env.state.innerReads;
    env.document.visibilityState = "visible";
    env.events.visibilitychange();
    assert.equal(env.state.innerReads, reads + 1);
    assert.equal(env.state.sent, 2);
    assert.equal(env.timers.size, 1);
});

test("only the top frame and Duo-hosted frames watch for challenges", () => {
    const embedded = environment({ top: false });
    const inactive = embedded.create();
    assert.equal(inactive.enabled, false);
    assert.equal(embedded.state.listener, null);
    assert.equal(embedded.timers.size, 0);
    assert.equal(embedded.state.textReads, 0);
    inactive.mutated();
    inactive.dispose();

    const duoFrame = environment({ top: false, href: "https://api-test.duosecurity.com/frame", text: "Push sent" });
    const duo = duoFrame.create();
    assert.equal(duo.enabled, true);
    assert.equal(duoFrame.state.textReads, 0, "Duo's own pages skip the Duo-name prefilter");
    assert.equal(duoFrame.state.innerReads, 1);
    assert.equal(duoFrame.state.sent, 1);
    duo.dispose();
});

test("a script left behind by an extension reload stops polling", () => {
    const env = environment({ text: "Duo Push: Check your phone" });
    let valid = true;
    env.create({ alive: () => valid });
    assert.equal(env.state.sent, 1);
    valid = false;
    env.tick();
    assert.equal(env.state.sent, 1);
    assert.equal(env.timers.size, 0);
});

test("a challenge stops being reported after five minutes on the same page", () => {
    const env = environment({ text: "Duo Push: Check your phone" });
    let now = Date.now();
    env.context.Date = { now: () => now };
    env.create();
    now += 5 * 60_000;
    env.tick();
    assert.equal(env.state.sent, 1);
    assert.equal(env.timers.size, 0);
});
