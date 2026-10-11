const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const [major, minor] = process.versions.node.split(".").map(Number);
if (major < 26 || (major === 26 && minor < 7)) throw new Error("Validation requires Node.js 26.7 or newer");
function run(command, args, announce = true) {
    if (announce) console.log(`\n> ${command} ${args.join(" ")}`);
    const result = spawnSync(command, args, { cwd: root, stdio: "inherit" });
    if (result.error) throw result.error;
    if (result.status !== 0) process.exit(result.status || 1);
}

run("cargo", ["fmt", "--all", "--", "--check"]);
run("cargo", ["run", "--locked", "--", "generate-command-reference", "--check"]);
const manifest = JSON.parse(fs.readFileSync(path.join(root, "extension/manifest.json"), "utf8"));
for (const entry of [manifest.background.service_worker, manifest.action.default_popup,
    ...manifest.content_scripts.flatMap(script => script.js)]) {
    if (!fs.statSync(path.join(root, "extension", entry)).isFile()) throw new Error(`Missing extension entry: ${entry}`);
}
// Check every script, including extracted services and browser-test helpers.
console.log("\n> Check all extension scripts");
for (const entry of fs.readdirSync(path.join(root, "extension"), { recursive: true }).sort()) {
    if (/\.(?:js|cjs)$/.test(entry)) run(process.execPath, ["--check", path.join("extension", entry)], false);
}
run(process.execPath, ["extension/check_unit_coverage.cjs"]);
run("cargo", ["test", "--locked", "--all-features"]);
run("cargo", ["clippy", "--locked", "--all-targets", "--all-features", "--", "-D", "warnings"]);
