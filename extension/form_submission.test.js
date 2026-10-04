const test = require("node:test");
const assert = require("node:assert/strict");
const { createSubmissionCoordinator, scheduleCredentialAdvance } = require("./form_submission.js");

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

test("matched, unmatched, and failed lookups never affect the site's submit event", async () => {
    for (const outcome of ["matched", "unmatched", "error"]) {
        const context = setup({ handle: async () => {
            if (outcome === "error") throw new Error("bridge failed");
            return { action: outcome };
        } });
        if (outcome === "error") await assert.rejects(context.coordinator.onSubmit(context.event), /bridge failed/);
        else await context.coordinator.onSubmit(context.event);
        assert.deepEqual(context.calls, [], outcome);
    }
});

test("later user attempts are handled without replaying a submission", async () => {
    const context = setup({ handle: async ({ submitter, credentials }) => {
        assert.equal(submitter, context.event.submitter);
        assert.deepEqual(credentials, { username: "alice", password: "secret" });
        context.calls.push("handle");
    } });
    await context.coordinator.onSubmit(context.event);
    await context.coordinator.onSubmit(context.event);
    assert.deepEqual(context.calls, ["handle", "handle"]);
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
