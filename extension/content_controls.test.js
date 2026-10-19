const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

test("credential filling preserves literal None usernames and omits only absent values", () => {
    const context = vm.createContext({ module: { exports: {} }, require, AbortController });
    vm.runInContext(fs.readFileSync(require.resolve("./content_controls.js"), "utf8"), context);
    context.api = context.module.exports.create({ bridge: {}, credentials: {}, autofill: {} });
    for (const username of ["None", "  username  ", "", null, undefined]) {
        context.account = { username };
        assert.equal(vm.runInContext("api.accountUsername(account)", context), username || "");
    }
});
