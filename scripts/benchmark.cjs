#!/usr/bin/env node
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { spawnSync, execFileSync } = require("node:child_process");
const root = path.resolve(__dirname, "..");
const args = process.argv.slice(2);
if (args.includes("--help")) {
    console.log("Usage: npm run bench -- [--quick] [--suite all|core|desktop|browser] [--profile release|dev] [--sizes 100,1000,10000] [--samples 9] [--sample-ms 20] [--output DIR] [--baseline SUMMARY.json]\nSaves timings and machine/build metadata. No timing thresholds are enforced.");
    process.exit(0);
}
const options = { suite: "all", profile: "release", sizes: "100,1000,10000", samples: 9, sampleMs: 20 };
for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--quick") Object.assign(options, { sizes: "100,1000", samples: 3, sampleMs: 2 });
    else {
        const key = { "--suite": "suite", "--profile": "profile", "--sizes": "sizes", "--samples": "samples", "--sample-ms": "sampleMs", "--output": "output", "--baseline": "baseline" }[arg];
        if (!key || !args[i + 1] || args[i + 1].startsWith("--")) throw new Error(`Unknown or incomplete option ${arg}`);
        options[key] = args[++i];
    }
}
const sizes = options.sizes.split(",").map(Number);
if (!sizes.length || sizes.some(n => !Number.isInteger(n) || n < 1 || n > 100000) || new Set(sizes).size !== sizes.length) throw new Error("Sizes must be distinct integers in 1..100000");
for (const [key, minimum, maximum] of [["samples", 3, 100], ["sampleMs", 1, 1000]]) {
    options[key] = Number(options[key]);
    if (!Number.isInteger(options[key]) || options[key] < minimum || options[key] > maximum) throw new Error(`Invalid ${key}`);
}
if (!["all", "core", "desktop", "browser"].includes(options.suite) || !["release", "dev"].includes(options.profile)) throw new Error("Invalid suite or profile");
const suites = options.suite === "all" ? ["core", "desktop", "browser"] : [options.suite];
const previous = options.baseline ? JSON.parse(fs.readFileSync(path.resolve(root, options.baseline), "utf8")) : null;
if (previous && (previous.schema_version !== 1 || previous.workload_version !== 2 || previous.manifest?.status !== "passed")) throw new Error("Incompatible or incomplete baseline report");
if (previous && previous.manifest.options.profile !== options.profile) throw new Error("Cannot compare Rust build profiles");
const output = path.resolve(root, options.output || `test-results/benchmarks/${new Date().toISOString().replace(/[:.]/g, "-")}`);
fs.mkdirSync(output, { recursive: true });
if (fs.readdirSync(output).length) throw new Error("Choose a fresh output directory; existing benchmark results are never overwritten");
function version(command, argv) { try { return execFileSync(command, argv, { cwd: root, encoding: "utf8" }).trim(); } catch { return "unavailable"; } }
// Fingerprint authored workload/production sources without copying source or
// configuration contents into the report. Dirty checkouts remain identifiable.
function sourceFingerprint() {
    const fingerprint = crypto.createHash("sha256");
    const sourceFiles = execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z", "src", "crates/pm-contracts", "crates/pm-platform", "crates/pm-client", "extension", "Cargo.toml", "Cargo.lock", "package.json", "package-lock.json", "scripts/benchmark.cjs", "scripts/benchmark_browser.cjs"], { cwd: root, encoding: "utf8" }).split("\0").filter(Boolean).sort();
    for (const file of sourceFiles) {
        const full = path.join(root, file);
        if (fs.statSync(full).isFile()) fingerprint.update(file).update("\0").update(fs.readFileSync(full)).update("\0");
    }
    return fingerprint.digest("hex");
}
const manifest = {
    schema_version: 1, workload_version: 2, status: "running", started_at: new Date().toISOString(),
    options: { ...options, sizes }, suites,
    machine: { platform: process.platform, release: os.release(), arch: process.arch, cpu: os.cpus()[0]?.model, logical_cpus: os.cpus().length },
    runtime: { node: process.version, rustc: suites.some(s => s !== "browser") ? version("rustc", ["--version"]) : null },
    source: { fingerprint: sourceFingerprint(), revision: version("git", ["rev-parse", "HEAD"]), dirty: Boolean(version("git", ["status", "--porcelain"])) },
};
const writeManifest = () => fs.writeFileSync(path.join(output, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
writeManifest();
console.log(`Benchmark report: ${output}`);
const records = [];
try {
    for (const suite of suites) {
        const report = path.join(output, `${suite}.jsonl`);
        if (fs.existsSync(report)) throw new Error(`Existing suite report: ${report}`);
        const env = { ...process.env, PM_BENCH_SIZES: sizes.join(","), PM_BENCH_SAMPLES: String(options.samples), PM_BENCH_SAMPLE_MS: String(options.sampleMs), PM_BENCH_OUTPUT: report,
            PM_DATA_DIR: path.join(output, "isolated-profile/data"), PM_CONFIG_DIR: path.join(output, "isolated-profile/config") };
        const command = suite === "browser" ? process.execPath : "cargo";
        const argv = suite === "browser" ? [path.join(__dirname, "benchmark_browser.cjs")] : [
            "test", "--locked", ...(options.profile === "release" ? ["--release"] : []),
            ...(suite === "core" ? ["--no-default-features", "--lib"] : ["--bin", "pm"]),
            "performance_benchmarks", "--", "--ignored", "--nocapture", "--test-threads=1"
        ];
        const detail = suite === "browser" ? "" : ` (${options.profile}; first compilation can take several minutes)`;
        console.log(`Running ${suite}${detail}…`);
        const result = spawnSync(command, argv, { cwd: root, env, encoding: "utf8", timeout: 1800000, maxBuffer: 16 * 1024 * 1024 });
        fs.writeFileSync(path.join(output, `${suite}.log`), (result.stdout || "") + (result.stderr || ""));
        if (result.error || result.status !== 0) throw new Error(`${suite} failed: ${result.error?.message || `exit ${result.status}`}; see ${path.join(output, `${suite}.log`)}`);
        if (!fs.existsSync(report)) throw new Error(`${suite} produced no measurements (benchmark filter may not match)`);
        const measured = fs.readFileSync(report, "utf8").trim().split("\n").map(line => JSON.parse(line));
        const expectedNames = {
            core: ["serialize_full", "serialize_one_item_overlay", "search_cold", "search_warm", "search_notes", "import_portable", "browser_matching_warm", "audit_cold", "mutation_durable", "batch_mutation_durable", "export_json_streamed"],
            desktop: ["directory_forced_scan", "directory_cached"],
            browser: ["dom_initial", "dom_attributes", "dom_structural", "controls_position"]
        }[suite];
        if (measured.length !== sizes.length * expectedNames.length) throw new Error(`Incomplete ${suite} results`);
        for (const size of sizes) for (const name of expectedNames) {
            const matches = measured.filter(r => r.size === size && r.name === name && r.suite === suite);
            if (matches.length !== 1 || matches[0].schema_version !== 1 || matches[0].unit !== "ns/op" || !Number.isFinite(matches[0].median_ns) || matches[0].median_ns <= 0) throw new Error(`Invalid result ${suite}/${name}/${size}`);
        }
        records.push(...measured);
        manifest.completed_suites = [...(manifest.completed_suites || []), suite]; writeManifest();
        console.log(`${suite}: ${measured.length} measurements saved`);
    }
    const summary = { schema_version: 1, workload_version: 2, manifest, records };
    if (options.baseline) {
        const comparisons = records.map(record => {
            const base = previous.records.find(r => r.suite === record.suite && r.name === record.name && r.size === record.size);
            if (!base || base.schema_version !== record.schema_version || base.unit !== record.unit || base.optimized !== record.optimized || !Number.isFinite(base.median_ns) || base.median_ns <= 0) throw new Error(`Baseline lacks ${record.suite}/${record.name}/${record.size}`);
            return { suite: record.suite, name: record.name, size: record.size, baseline_median_ns: base.median_ns, current_median_ns: record.median_ns, change_percent: (record.median_ns / base.median_ns - 1) * 100 };
        });
        fs.writeFileSync(path.join(output, "comparison.json"), JSON.stringify({ note: "Negative changes mean faster. Compare on the same machine with similar load; no significance test or regression threshold is implied.", baseline: path.resolve(root, options.baseline), environment_changed: JSON.stringify(previous.manifest.machine) !== JSON.stringify(manifest.machine) || JSON.stringify(previous.manifest.runtime) !== JSON.stringify(manifest.runtime) || records.some(record => record.suite === "browser" && previous.records.find(r => r.suite === record.suite && r.name === record.name && r.size === record.size)?.browser !== record.browser), comparisons }, null, 2) + "\n");
    }
    if (sourceFingerprint() !== manifest.source.fingerprint) throw new Error("Sources changed during benchmarks; rerun against a stable checkout");
    manifest.status = "passed"; manifest.finished_at = new Date().toISOString(); writeManifest();
    fs.writeFileSync(path.join(output, "summary.json"), JSON.stringify(summary, null, 2) + "\n");
    console.log(`Passed. Summary: ${path.join(output, "summary.json")}`);
} catch (error) {
    manifest.status = "failed"; manifest.error = error.message; writeManifest();
    console.error(error.message); process.exitCode = 1;
}
