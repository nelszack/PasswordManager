const test = require("node:test");
const assert = require("node:assert/strict");
const { createCredentialAttempt, createSubmissionCoordinator, scheduleCredentialAdvance } = require("./form_submission.js");

function setup({ password = "secret", handle = async () => {}, shouldIgnore = () => false,
    userActivated = () => true } = {}) {
    const form = {};
    const calls = [];
    const coordinator = createSubmissionCoordinator({
        isForm: value => value === form,
        credentialsFor: () => ({ username: "alice", password }),
        shouldIgnore, userActivated, handle
    });
    const event = { target: form, submitter: {}, isTrusted: true,
        preventDefault: () => calls.push("prevent") };
    return { coordinator, event, calls };
}

test("pending prompts never prevent submission and duplicate attempts pass through", async () => {
    let release;
    const pending = new Promise(resolve => { release = resolve; });
    const context = setup({ handle: async () => { context.calls.push("handle"); await pending; } });
    const first = context.coordinator.onSubmit(context.event);
    assert.deepEqual(context.calls, ["handle"], "sends before navigation without preventing submission");
    await context.coordinator.onSubmit(context.event);
    assert.deepEqual(context.calls, ["handle"]);
    release(); await first;
    assert.deepEqual(context.calls, ["handle"]);
});

test("trusted script-driven submits without user activation do not request vault data", async () => {
    for (const scenario of ["synthetic", "no-activation", "passwordless", "ignored", "non-form"]) {
        const context = setup({ password: scenario === "passwordless" ? "" : "secret",
            userActivated: () => scenario !== "no-activation", shouldIgnore: () => scenario === "ignored",
            handle: async () => context.calls.push("handle") });
        if (scenario === "synthetic") context.event.isTrusted = false;
        if (scenario === "non-form") context.event.target = {};
        await context.coordinator.onSubmit(context.event);
        assert.deepEqual(context.calls, [], scenario);
    }
});

test("later submissions preserve their payload and never replay the site's submit", async t => {
    for (const firstResult of ["success", "failure"]) await t.test(firstResult, async () => {
        let fail = firstResult === "failure";
        const context = setup({ handle: async ({ submitter, credentials }) => {
            assert.equal(submitter, context.event.submitter);
            assert.deepEqual(credentials, { username: "alice", password: "secret" });
            context.calls.push("handle");
            if (fail) throw new Error("bridge failed");
        } });
        const first = context.coordinator.onSubmit(context.event);
        if (fail) await assert.rejects(first, /bridge failed/); else await first;
        assert.deepEqual(context.calls, ["handle"]);
        fail = false;
        await context.coordinator.onSubmit(context.event);
        assert.deepEqual(context.calls, ["handle", "handle"]);
    });
});

test("multi-step advances remember usernames and prompt only from a captured password", () => {
    for (const password of ["", "secret"]) {
        const calls = [];
        const credentials = { username: "alice", password };
        scheduleCredentialAdvance(credentials, {
            remember: username => calls.push(["remember", username]),
            shouldIgnore: () => false,
            prompt: captured => calls.push(["prompt", captured]),
            defer: callback => callback()
        });
        const expected = [["remember", "alice"]];
        if (password) expected.push(["prompt", credentials]);
        assert.deepEqual(calls, expected, password || "username-only step");
    }
});

test("normal form submission suppresses the scripted-advance fallback", () => {
    const calls = [];
    let deferred;
    scheduleCredentialAdvance({ username: "alice", password: "secret" }, {
        remember: () => {},
        shouldIgnore: () => true,
        prompt: () => calls.push("prompt"),
        defer: callback => { deferred = callback; }
    });
    deferred();
    assert.deepEqual(calls, []);
});

test("all submission sources share one attempt and only skipped or failed prompts permit retry", async () => {
    let finish, calls = 0;
    const attempt = createCredentialAttempt(() => { calls++; return new Promise(resolve => { finish = resolve; }); });
    const first = attempt.run({ password: "synthetic" });
    await attempt.run({ password: "duplicate" });
    assert.equal(calls, 1);
    assert.equal(attempt.reserve(), false, "navigation cannot duplicate an in-flight prompt");
    finish({ action: "skipped" }); await first;
    assert.equal(attempt.idle, true);
    const next = attempt.run({ password: "synthetic" });
    finish({ action: "cancel" }); await next;
    assert.equal(attempt.idle, false, "a completed decision suppresses later submission sources");
    await attempt.run({ password: "duplicate" });
    assert.equal(calls, 2);
    const failed = createCredentialAttempt(() => Promise.reject(new Error("offline")));
    await assert.rejects(failed.run({}), /offline/);
    assert.equal(failed.idle, true);
});

test("navigation reserves the attempt and disposal cannot be undone by a late skipped result", async () => {
    const navigation = createCredentialAttempt(() => assert.fail("already reserved"));
    assert.equal(navigation.reserve(), true);
    await navigation.run({});
    navigation.dispose();
    assert.equal(navigation.reserve(), false);
    let finish;
    const attempt = createCredentialAttempt(() => new Promise(resolve => { finish = resolve; }));
    const pending = attempt.run({});
    attempt.dispose();
    finish({ action: "skipped" }); await pending;
    assert.equal(attempt.idle, false);
    assert.equal(attempt.reserve(), false);
});

function advanceClock() {
    const clock = { now: 0, timers: [] };
    clock.options = {
        now: () => clock.now,
        setTimeout: (callback, delay) => {
            const timer = { callback, at: clock.now + delay };
            clock.timers.push(timer);
            return timer;
        },
        clearTimeout: timer => {
            clock.timers = clock.timers.filter(candidate => candidate !== timer);
        },
    };
    clock.run = until => {
        while (clock.timers.length) {
            clock.timers.sort((a, b) => a.at - b.at);
            if (clock.timers[0].at > until) break;
            const timer = clock.timers.shift();
            clock.now = timer.at;
            timer.callback();
        }
        clock.now = Math.max(clock.now, until);
    };
    return clock;
}

test("non-submit advances prompt only after the page leaves the password step", () => {
    for (const [label, leavesAt, expected] of [
        ["removed after 120 ms", 120, 1],
        ["still on the password step after 500 ms", Infinity, 0],
        ["left too late", 600, 0],
    ]) {
        const clock = advanceClock();
        const prompts = [];
        const remembered = [];
        const watch = scheduleCredentialAdvance(
            { username: "alice", password: "secret" },
            {
                ...clock.options,
                remember: username => remembered.push(username),
                shouldIgnore: () => false,
                advanced: () => clock.now >= leavesAt,
                prompt: credentials => prompts.push(credentials),
            }
        );
        assert.deepEqual(remembered, ["alice"], label);
        assert.equal(prompts.length, 0, `${label}: nothing opens before confirmation`);
        assert.equal(watch.pending, true);
        clock.run(1000);
        assert.equal(prompts.length, expected, label);
        assert.equal(watch.pending, false);
        assert.equal(clock.timers.length, 0, `${label}: polling stops`);
    }
});

test("page hide confirms a pending advance and cancellation drops it", () => {
    for (const action of ["confirm", "cancel"]) {
        const clock = advanceClock();
        const prompts = [];
        const watch = scheduleCredentialAdvance(
            { username: "", password: "secret" },
            {
                ...clock.options,
                remember: () => assert.fail("no username to remember"),
                shouldIgnore: () => false,
                advanced: () => false,
                prompt: credentials => prompts.push(credentials),
            }
        );
        assert.deepEqual(watch.credentials, { username: "", password: "secret" });
        watch[action]();
        watch.confirm();
        clock.run(1000);
        assert.equal(prompts.length, action === "confirm" ? 1 : 0, action);
    }
    const clock = advanceClock();
    const ignored = scheduleCredentialAdvance(
        { username: "", password: "secret" },
        { ...clock.options, remember() {}, shouldIgnore: () => true, advanced: () => true, prompt: () => assert.fail() }
    );
    clock.run(1000);
    assert.equal(ignored.pending, false);
    assert.equal(
        scheduleCredentialAdvance({ username: "", password: "" }, { remember() {}, advanced: () => true }),
        null,
        "a click without a password has nothing to confirm"
    );
});
