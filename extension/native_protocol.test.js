const test = require("node:test");
const assert = require("node:assert/strict");
const protocol = require("./native_protocol.js");

test("native response envelopes reject malformed or ambiguous values", () => {
    const valid = { id: 7, success: true, data: "Status: Locked" };
    assert.equal(protocol.validateResponse(valid), valid);
    for (const [label, response] of [
        ["missing envelope", null],
        ["string request ID", { id: "7", success: true, data: "ok" }],
        ["nonboolean success", { id: 7, success: "yes", data: "ok" }],
        ["missing result", { id: 7, success: true }],
        ["empty error", { id: 7, success: false, error: "" }],
        ["nonboolean uncertainty", { id: 7, success: false, error: "failed", uncertain: "yes" }],
        ["successful uncertain result", { id: 7, success: true, data: {}, uncertain: true }]
    ]) assert.throws(() => protocol.validateResponse(response), /Invalid native/, label);
    const uncertain = { id: 7, success: false, error: "Review the vault", uncertain: true };
    assert.equal(protocol.validateResponse(uncertain), uncertain);
});

test("native item payloads require a successful array response", () => {
    assert.deepEqual(protocol.parseItems({ success: true, data: [{"id": 1}] }), [{ id: 1 }]);
    for (const [label, data] of [["encoded string", "not-json"], ["object", {}], ["null", null]]) {
        assert.throws(() => protocol.parseItems({ success: true, data }), /Invalid vault/, label);
    }
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

test("unlock session identifiers reject missing and malformed response bindings", () => {
    for (const sessionId of [undefined, null, "", "a".repeat(63), "z".repeat(64), 1]) {
        assert.throws(() => protocol.sessionId({ sessionId }), /Unlock session unavailable/);
    }
    const sessionId = "a".repeat(64);
    assert.equal(protocol.sessionId({ sessionId }), sessionId);
    assert.throws(() => protocol.validateResponse({ id: 1, success: true, data: [], sessionId: "bad" }), /Unlock session unavailable/);
    assert.equal(protocol.validateResponse({ id: 1, success: true, data: [], sessionId }).sessionId, sessionId);
});
