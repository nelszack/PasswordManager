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

test("submission is cancelled synchronously before asynchronous work", async () => {
    let release;
    const pending = new Promise(resolve => { release = resolve; });
    const context = setup({
        handle: async () => {
            context.calls.push("handle");
            await pending;
        }
    });

    const result = context.coordinator.onSubmit(context.event);
    assert.deepEqual(context.calls, ["prevent", "handle"]);
    release();
    await result;
    assert.deepEqual(context.calls, ["prevent", "handle", "resume"]);
});

test("synthetic submissions cannot open a credential prompt", async () => {
    const context = setup();
    context.event.isTrusted = false;
    await context.coordinator.onSubmit(context.event);
    assert.deepEqual(context.calls, []);
});

test("passwordless forms are not intercepted", async () => {
    const context = setup({ password: "" });
    await context.coordinator.onSubmit(context.event);
    assert.deepEqual(context.calls, []);
});

test("errors still resume the user's submission", async () => {
    const context = setup({ handle: async () => { throw new Error("bridge failed"); } });
    await assert.rejects(context.coordinator.onSubmit(context.event), /bridge failed/);
    assert.deepEqual(context.calls, ["prevent", "resume"]);
});

test("the resumed submit event passes through once", async () => {
    const context = setup();
    await context.coordinator.onSubmit(context.event);
    await context.coordinator.onSubmit(context.event);
    assert.deepEqual(context.calls, ["prevent", "resume"]);
});

test("concurrent submissions are blocked without opening duplicate prompts", async () => {
    let release;
    const pending = new Promise(resolve => { release = resolve; });
    const context = setup({
        handle: async () => {
            context.calls.push("handle");
            await pending;
        }
    });

    const first = context.coordinator.onSubmit(context.event);
    await context.coordinator.onSubmit(context.event);
    assert.deepEqual(context.calls, ["prevent", "handle", "prevent"]);

    release();
    await first;
    assert.deepEqual(context.calls, ["prevent", "handle", "prevent", "resume"]);
});

test("ignored and non-form submissions pass through", async () => {
    const ignored = setup({ shouldIgnore: () => true });
    await ignored.coordinator.onSubmit(ignored.event);
    assert.deepEqual(ignored.calls, []);

    const notAForm = setup();
    notAForm.event.target = {};
    await notAForm.coordinator.onSubmit(notAForm.event);
    assert.deepEqual(notAForm.calls, []);
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
    await context.coordinator.onSubmit(context.event); // requestSubmit replay
    await context.coordinator.onSubmit(context.event); // a new user attempt
    assert.deepEqual(context.calls, [
        "prevent", "handle", "resume",
        "prevent", "handle", "resume"
    ]);
});

test("multi-step advances remember usernames before navigation", () => {
    const calls = [];
    scheduleCredentialAdvance({ username: "alice", password: "" }, {
        remember: username => calls.push(["remember", username]),
        shouldIgnore: () => false,
        prompt: () => calls.push(["prompt"]),
        defer: callback => callback()
    });
    assert.deepEqual(calls, [["remember", "alice"]]);
});

test("scripted password advances prompt from the captured snapshot", () => {
    const calls = [];
    const credentials = { username: "alice", password: "secret" };
    scheduleCredentialAdvance(credentials, {
        remember: username => calls.push(["remember", username]),
        shouldIgnore: () => false,
        prompt: captured => calls.push(["prompt", captured]),
        defer: callback => callback()
    });
    assert.deepEqual(calls, [
        ["remember", "alice"],
        ["prompt", credentials]
    ]);
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
