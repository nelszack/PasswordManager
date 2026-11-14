const test = require("node:test");
const assert = require("node:assert/strict");
const { loadScript } = require("./test_harness.cjs");

function transport(sendMessage, lastError) {
    const context = { chrome: { runtime: { sendMessage, lastError } } };
    loadScript("ui_transport.js", context);
    return context.PasswordManagerUiTransport;
}

test("UI transport preserves uncertain outcomes and never retries a failed mutation", async () => {
    const response = { success: false, uncertain: true, error: "Review the outcome" };
    let calls = 0;
    const ui = transport((_message, done) => { calls++; done(response); });
    assert.equal(await ui.send({ action: "saveCredentials" }), response);
    assert.equal(calls, 1);
    await assert.rejects(ui.request({}, "Unavailable"), /Review the outcome/);
});

test("UI transport handles disconnects, missing replies, and synchronous failures", async () => {
    for (const [label, ui] of [
        ["disconnect", transport((_message, done) => done(), { message: "Disconnected" })],
        ["missing reply", transport((_message, done) => done())],
        ["synchronous failure", transport(() => { throw new Error("Worker stopped"); })]
    ]) {
        const response = await ui.send({});
        assert.equal(response.success, false, label);
        assert.ok(response.error, label);
    }
    const response = { success: true, data: "ok" };
    assert.equal(await transport((_message, done) => done(response)).request({}), response);
    await assert.rejects(transport((_message, done) => done({ success: false })).request({}, "Unavailable"), /Unavailable/);
});
