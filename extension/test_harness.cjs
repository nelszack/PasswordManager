// Execute authored scripts in a caller-owned isolated browser/worker context.
// Keeping the real filename preserves production-file coverage attribution.
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
function loadScript(name, context) {
    const filename = path.resolve(__dirname, name);
    const isolated = vm.isContext(context) ? context : vm.createContext(context);
    return vm.runInContext(fs.readFileSync(filename, "utf8"), isolated, { filename });
}
module.exports = { loadScript };
