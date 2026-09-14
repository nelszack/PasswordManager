const test = require("node:test");
const assert = require("node:assert/strict");
const { createSubmissionCoordinator } = require("./form_submission.js");

function setup({ password = "secret", handle = async () => {} } = {}) {
    const form = {};
    const calls = [];
    const coordinator = createSubmissionCoordinator({
        isForm: value => value === form,
        credentialsFor: () => ({ username: "alice", password }),
        shouldIgnore: () => false,
        handle,
        resume: () => calls.push("resume")
    });
    const event = {
        target: form,
        submitter: {},
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
