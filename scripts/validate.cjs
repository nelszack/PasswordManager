const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const [major, minor] = process.versions.node.split(".").map(Number);
if (major < 26 || (major === 26 && minor < 7)) throw new Error("Validation requires Node.js 26.7 or newer");
function run(command, args, announce = true, artifacts = null) {
    if (announce) console.log(`\n> ${command} ${args.join(" ")}`);
    const result = spawnSync(command, args, {
        cwd: root,
        stdio: artifacts ? ["inherit", "pipe", "inherit"] : "inherit",
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024
    });
    if (artifacts && result.stdout) {
        for (const line of result.stdout.split("\n")) {
            let message;
            try { message = JSON.parse(line); } catch { /* Test output is plain text. */ }
            if (message?.reason === "compiler-artifact") artifacts.push(message);
            if (!["compiler-artifact", "build-script-executed", "build-finished"].includes(message?.reason)) {
                process.stdout.write(`${line}\n`);
            }
        }
    }
    if (result.error) throw result.error;
    if (result.status !== 0) process.exit(result.status || 1);
}

run(process.execPath, ["scripts/build_extension.cjs", "--check"]);
run("cargo", ["fmt", "--all", "--", "--check"]);
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
const artifacts = [];
run("cargo", ["test", "--locked", "-p", "iced_tiny_skia", "--lib"]);
run("cargo", ["test", "--locked", "--all-features", "--message-format=json-render-diagnostics"], true, artifacts);
// Cargo reports the exact executable path, including custom target directories
// and platform suffixes. Reuse it without another build or feature resolution.
const executable = artifacts.find(artifact => artifact.target.name === "pm"
    && artifact.target.kind.includes("bin") && !artifact.profile.test && artifact.executable)?.executable;
if (!executable) throw new Error("Cargo did not report the pm integration-test executable");
run(executable, ["generate-command-reference", "--check"]);
run(executable, ["generate-command-contract", "--check"]);
run("cargo", ["clippy", "--locked", "--all-targets", "--all-features", "--", "-D", "warnings"]);
