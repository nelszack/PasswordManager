const test = require("node:test");
const assert = require("node:assert/strict");
const contract = require("./command_contract.js");
const { summary, nativeFields } = require("./test_fixtures.cjs");

test("generated native request policy rejects cross-operation fields, missing revisions and malformed nested values", () => {
    const mutation = { ...nativeFields("updateCredentials"), operationId: "reviewed-save" };
    assert.equal(contract.validateRequest("updateCredentials", mutation), mutation);
    for (const invalid of [
        { ...mutation, expectedRevision: undefined },
        { ...mutation, expectedRevision: -1 },
        { ...mutation, entryId: "1" },
        { ...mutation, operationId: "" },
        { ...mutation, action: "lock" },
        { ...mutation, password: {} }
    ]) assert.throws(() => contract.validateRequest("updateCredentials", invalid));
    assert.throws(() => contract.validateRequest("getLoginItems", { password: "secret" }));
    assert.throws(() => contract.validateRequest("managerUnlock", { operationId: "unlock", password: "master", keyPath: "/tmp/key" }));
    assert.deepEqual(contract.operations.saveCredentials.allowedSenders, ["background"]);
    assert.deepEqual(contract.operations.updateCredentials.allowedSenders, ["background"]);
});

test("generated result decoders distinguish summaries, details, authenticator modes and identified receipts", () => {
    assert.equal(contract.validateResult("getLoginItems", [summary()]).length, 1);
    for (const invalid of ["[]", [summary({ revision: undefined })], [{ id: 1, password: "wrong-shaped-data" }]]) {
        assert.throws(() => contract.validateResult("getLoginItems", invalid));
    }
    assert.throws(() => contract.validateResult("getTotp", { mode: "hotp", code: "123456", expires_in: 24, counter: 1 }));
    assert.equal(contract.validateResult("getTotp", { mode: "totp", code: "123456", expires_in: 24, counter: null }).mode, "totp");
    assert.throws(() => contract.validateResult("operationStatus", { state: "committed", revision: 1 }));
    assert.equal(contract.validateResult("operationStatus", { state: "unknown", operationId: "save-id", revision: null }).state, "unknown");
});

test("HOTP results preserve the full unsigned 64-bit counter as canonical decimal text", () => {
    const result = { mode: "hotp", code: "123456", expires_in: null };
    for (const counter of ["0", "9007199254740991", "9007199254740992", "18446744073709551615"]) {
        assert.equal(contract.validateResult("getTotp", { ...result, counter }).counter, counter);
    }
    for (const counter of [0, 9007199254740992, "", "00", "+1", "-1", " 1", "1.0", "1e3", "18446744073709551616"]) {
        assert.throws(() => contract.validateResult("getTotp", { ...result, counter }));
    }
});
