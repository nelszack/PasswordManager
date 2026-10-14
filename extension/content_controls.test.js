const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

test("credential filling preserves literal None usernames and omits only absent values", () => {
    const context = vm.createContext({});
    vm.runInContext(fs.readFileSync(require.resolve("./content_controls.js"), "utf8"), context);
    for (const username of ["None", "  username  ", "", null, undefined]) {
        context.account = { username };
        assert.equal(vm.runInContext("accountUsername(account)", context), username || "");
    }
});
