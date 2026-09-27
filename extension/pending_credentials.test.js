const test = require("node:test");
const assert = require("node:assert/strict");
const pending = require("./pending_credentials.js");

test("session-backed pending secrets survive a worker restart but remain origin-bound", () => {
    const stored = pending.create({ username: "alice", password: "secret" }, "https://example.com", 1000);
    const afterRestart = structuredClone(stored);
    assert.equal(pending.usable(afterRestart, "https://example.com", 2000), true);
    assert.equal(pending.usable(afterRestart, "https://attacker.example", 2000), false);
});

test("pending secrets expire and malformed timestamps fail closed", () => {
    const stored = pending.create({ password: "secret" }, "https://example.com", 1000);
    assert.equal(pending.usable(stored, "https://example.com", 1000 + pending.MAX_AGE_MS - 1), true);
    assert.equal(pending.usable(stored, "https://example.com", 1000 + pending.MAX_AGE_MS), false);
    assert.equal(pending.usable({ ...stored, time: "1000" }, "https://example.com", 2000), false);
    assert.equal(pending.usable(stored, "https://example.com", 999), false);
    assert.throws(() => pending.create({}, "https://example.com"));
});
