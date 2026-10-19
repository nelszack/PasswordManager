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
    assert.throws(() => protocol.validateResponse({ id: 7, success: false, error: "failed", uncertain: "yes" }));
    assert.throws(() => protocol.validateResponse({ id: 7, success: true, data: {}, uncertain: true }));
    const uncertain = { id: 7, success: false, error: "Review the vault", uncertain: true };
    assert.equal(protocol.validateResponse(uncertain), uncertain);
});

test("native item payloads require a successful JSON array response", () => {
    assert.deepEqual(protocol.parseItems({ success: true, data: [{"id": 1}] }), [{ id: 1 }]);
    assert.throws(() => protocol.parseItems({ success: true, data: "not-json" }), /Invalid vault/);
    assert.throws(() => protocol.parseItems({ success: true, data: {} }), /Invalid vault/);
    assert.throws(() => protocol.parseItems({ success: true, data: null }), /Invalid vault/);
    assert.throws(() => protocol.parseItems({ success: false, error: "Vault locked" }), /locked/);
});

test("missing and incompatible native protocol versions fail closed", () => {
    const response = { id: 1, success: true, data: [] };
    assert.throws(() => protocol.validateResponse(response, 1), /Incompatible native protocol/);
    assert.throws(() => protocol.validateResponse({ ...response, protocolVersion: 2 }, 1), /Incompatible native protocol/);
    assert.equal(protocol.validateResponse({ ...response, protocolVersion: 1 }, 1).protocolVersion, 1);
});

test("successful mutations require a committed receipt for the same operation identity", () => {
    const response = { id: 1, protocolVersion: 1, success: true, data: "Saved" };
    assert.throws(() => protocol.validateResponse(response, 1, "save-id"), /mutation receipt/);
    for (const receipt of [{ operationId: "other-id", state: "committed", revision: 1 }, { operationId: "save-id", state: "pending", revision: null }]) {
        assert.throws(() => protocol.validateResponse({ ...response, operation: receipt }, 1, "save-id"), /mutation receipt/);
    }
    assert.equal(protocol.validateResponse({ ...response, operation: { operationId: "save-id", state: "committed", revision: 1 } }, 1, "save-id").success, true);
});
