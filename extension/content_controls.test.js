const test = require("node:test");
const assert = require("node:assert/strict");
const { create } = require("./content_controls.js");

test("credential filling preserves literal None usernames and omits only absent values", () => {
    const { accountUsername } = create({ bridge: {}, credentials: {}, autofill: {} });
    for (const username of ["None", "  username  ", "", null, undefined]) {
        assert.equal(accountUsername({ username }), username || "");
    }
});
