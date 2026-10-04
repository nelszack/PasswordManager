const test = require("node:test");
const assert = require("node:assert/strict");
const {
    createSubmissionCoordinator,
    scheduleCredentialAdvance
} = require("./form_submission.js");

function setup({ password = "secret", handle = async () => {}, shouldIgnore = () => false } = {}) {
    const form = {};
    const calls = [];
    const coordinator = createSubmissionCoordinator({
        isForm: value => value === form,
        credentialsFor: () => ({ username: "alice", password }),
        shouldIgnore,
        handle,
        resume: () => calls.push("resume")
    });
    const event = {
        target: form,
        submitter: {},
        isTrusted: true,
        preventDefault: () => calls.push("prevent")
    };
    return { coordinator, event, calls };
}

test("submission is cancelled synchronously and concurrent attempts cannot duplicate prompts", async () => {
    let release;
    const pending = new Promise(resolve => { release = resolve; });
    const context = setup({
        handle: async () => {
            context.calls.push("handle");
            await pending;
        }
    });
    const first = context.coordinator.onSubmit(context.event);
    assert.deepEqual(context.calls, ["prevent", "handle"], "cancels before awaiting");
    await context.coordinator.onSubmit(context.event);
    assert.deepEqual(context.calls, ["prevent", "handle", "prevent"], "blocks concurrent submit");
    release();
    await first;
    assert.deepEqual(context.calls, ["prevent", "handle", "prevent", "resume"]);
});

test("synthetic, passwordless, ignored, and non-form submissions pass through", async () => {
    for (const scenario of ["synthetic", "passwordless", "ignored", "non-form"]) {
        const context = setup({
            password: scenario === "passwordless" ? "" : "secret",
            shouldIgnore: () => scenario === "ignored",
            handle: async () => context.calls.push("handle")
        });
        if (scenario === "synthetic") context.event.isTrusted = false;
        if (scenario === "non-form") context.event.target = {};
        await context.coordinator.onSubmit(context.event);
        assert.deepEqual(context.calls, [], scenario);
    }
});


test("errors still resume the user's submission", async () => {
    const context = setup({ handle: async () => { throw new Error("bridge failed"); } });
    await assert.rejects(context.coordinator.onSubmit(context.event), /bridge failed/);
    assert.deepEqual(context.calls, ["prevent", "resume"]);
});




test("a later user submission is handled after the resumed event", async () => {
    const context = setup({
        handle: async ({ submitter, credentials }) => {
            assert.equal(submitter, context.event.submitter);
            assert.deepEqual(credentials, { username: "alice", password: "secret" });
            context.calls.push("handle");
        }
    });

    await context.coordinator.onSubmit(context.event);
    assert.deepEqual(context.calls, ["prevent", "handle", "resume"]);
    await context.coordinator.onSubmit(context.event); // requestSubmit replay
    assert.deepEqual(context.calls, ["prevent", "handle", "resume"], "replay passes through once");
    await context.coordinator.onSubmit(context.event); // a new user attempt
    assert.deepEqual(context.calls, [
        "prevent", "handle", "resume",
        "prevent", "handle", "resume"
    ]);
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
