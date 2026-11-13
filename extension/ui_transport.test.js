const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");

function transport(sendMessage, lastError) {
    const context = { chrome: { runtime: { sendMessage, lastError } } };
    vm.runInNewContext(fs.readFileSync(`${__dirname}/ui_transport.js`, "utf8"), context);
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
    for (const ui of [
        transport((_message, done) => done(), { message: "Disconnected" }),
        transport((_message, done) => done()),
        transport(() => { throw new Error("Worker stopped"); })
    ]) {
        const response = await ui.send({});
        assert.equal(response.success, false);
        assert.ok(response.error);
    }
    const response = { success: true, data: "ok" };
    assert.equal(await transport((_message, done) => done(response)).request({}), response);
    await assert.rejects(transport((_message, done) => done({ success: false })).request({}, "Unavailable"), /Unavailable/);
});
