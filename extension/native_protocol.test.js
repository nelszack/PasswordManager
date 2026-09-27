const test = require("node:test");
const assert = require("node:assert/strict");
const protocol = require("./native_protocol.js");

test("native response envelopes reject malformed or ambiguous values", () => {
    const valid = { id: 7, success: true, data: "Status: Locked" };
    assert.equal(protocol.validateResponse(valid), valid);
    assert.throws(() => protocol.validateResponse(null), /Invalid native/);
    assert.throws(() => protocol.validateResponse({ id: "7", success: true, data: "ok" }));
    assert.throws(() => protocol.validateResponse({ id: 7, success: "yes", data: "ok" }));
    assert.throws(() => protocol.validateResponse({ id: 7, success: true }));
    assert.throws(() => protocol.validateResponse({ id: 7, success: false, error: "" }));
});

test("native item payloads require a successful JSON array response", () => {
    assert.deepEqual(protocol.parseItems({ success: true, data: '[{"id":1}]' }), [{ id: 1 }]);
    assert.throws(() => protocol.parseItems({ success: true, data: "not-json" }), /Invalid vault/);
    assert.throws(() => protocol.parseItems({ success: true, data: "{}" }), /Invalid vault/);
    assert.throws(() => protocol.parseItems({ success: true, data: null }), /Invalid vault/);
    assert.throws(() => protocol.parseItems({ success: false, error: "Vault locked" }), /locked/);
});
