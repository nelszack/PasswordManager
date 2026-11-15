const fs = require("node:fs");
const path = require("node:path");
const { spawnSync, spawn } = require("node:child_process");

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

// Bound process startup concurrency; each file still receives Node's native parser.
async function checkScripts(files) {
    let next = 0;
    const failures = new Map();
    await Promise.all(Array.from({ length: Math.min(4, require("node:os").availableParallelism()) }, async () => {
        while (next < files.length) {
            const file = files[next++];
            await new Promise(resolve => {
                const child = spawn(process.execPath, ["--check", file], { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
                let output = "";
                child.stdout.on("data", data => { output += data; });
                child.stderr.on("data", data => { output += data; });
                child.on("error", error => { failures.set(file, error.message); });
                child.on("close", code => {
                    if (code !== 0 && !failures.has(file)) failures.set(file, output || `exit ${code}`);
                    resolve();
                });
            });
        }
    }));
    for (const file of files) if (failures.has(file)) console.error(`${file}:\n${failures.get(file)}`);
    if (failures.size) throw new Error(`${failures.size} script syntax checks failed`);
}

async function main() {
    const mode = process.argv[2] || "all";
    if (process.argv.length > 3 || !["all", "rust", "extension"].includes(mode)) {
        throw new Error("Usage: node scripts/validate.cjs [all|rust|extension]");
    }

    if (mode !== "rust") {
        run(process.execPath, ["scripts/build_extension.cjs", "--check"]);
        run(process.execPath, ["scripts/package_extension.cjs", "--check"]);
        // Check every script, including extracted services and browser-test helpers.
        console.log("\n> Check all extension scripts");
        await checkScripts(fs.readdirSync(path.join(root, "extension"), { recursive: true }).sort()
            .filter(entry => /\.(?:js|cjs)$/.test(entry)).map(entry => path.join("extension", entry)));
        run(process.execPath, ["extension/check_unit_coverage.cjs"]);
    }
    if (mode !== "extension") {
        run("cargo", ["fmt", "--all", "--", "--check"]);
        run(process.platform === "win32" ? "python" : "python3", ["scripts/check_dependency_boundaries.py"]);
        const artifacts = [];
        // Exercise the small components independently of the application: their
        // tests must not accidentally rely on features enabled by the full build.
        run("cargo", ["test", "--locked", "-p", "pm-contracts", "-p", "pm-client", "-p", "pm-platform",
            "--features", "pm-platform/clipboard"]);
        // These desktop packages share the same resolved dependency features. Build and
        // run their harnesses together rather than resolving the graph for each one.
        const desktopPackages = ["iced_tiny_skia", "iced_winit"];
        if (process.platform === "linux") desktopPackages.push("accesskit_unix");
        run("cargo", ["test", "--locked", ...desktopPackages.flatMap(name => ["-p", name]), "--lib"]);
        if (process.platform === "linux") {
            // Keep workspace protocol packages separate: combining them changes their
            // dependency feature sets and stops testing the existing configurations.
            run("cargo", ["test", "--locked", "-p", "atspi-common", "--lib"]);
            run("cargo", ["test", "--locked", "-p", "zbus-lockstep", "--lib"]);
        }
        run("cargo", ["test", "--locked", "--all-features", "--message-format=json-render-diagnostics"], true, artifacts);
        // Cargo reports the exact executable path, including custom target directories
        // and platform suffixes. Reuse it without another build or feature resolution.
        const executable = artifacts.find(artifact => artifact.target.name === "pm"
            && artifact.target.kind.includes("bin") && !artifact.profile.test && artifact.executable)?.executable;
        if (!executable) throw new Error("Cargo did not report the pm integration-test executable");
        run(executable, ["generate-command-reference", "--check"]);
        run(executable, ["generate-command-contract", "--check"]);
        run("cargo", ["clippy", "--locked", "-p", "password_manager", "-p", "pm-contracts", "-p", "pm-client", "-p", "pm-platform", "--all-targets", "--all-features", "--", "-D", "warnings"]);
    }

}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
