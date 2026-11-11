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
