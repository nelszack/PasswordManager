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
// Run a CommonJS entry point and its relative requires inside the context, as the
// generated bundle would, while each file keeps its own name for coverage.
// `stubs` replaces modules by specifier (for example "./ui_session.js").
function loadModule(name, context, stubs = {}) {
    const isolated = vm.isContext(context) ? context : vm.createContext(context);
    const cache = new Map();
    function load(filename) {
        if (cache.has(filename)) return cache.get(filename).exports;
        const module = { exports: {} };
        cache.set(filename, module);
        const run = vm.compileFunction(fs.readFileSync(filename, "utf8"), ["module", "exports", "require"], {
            filename,
            parsingContext: isolated,
        });
        run(module, module.exports, specifier =>
            Object.hasOwn(stubs, specifier) ? stubs[specifier] : load(path.resolve(path.dirname(filename), specifier))
        );
        return module.exports;
    }
    return load(path.resolve(__dirname, name));
}
module.exports = { loadScript, loadModule };
