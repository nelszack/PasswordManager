const fs = require("node:fs");
const path = require("node:path");

const directory = path.resolve(process.argv[2] || "test-results/e2e-coverage");
if (!fs.existsSync(directory)) throw new Error(`Missing browser coverage directory: ${directory}`);

const scripts = new Map();
for (const file of fs.readdirSync(directory).filter(name => name.endsWith(".json"))) {
    for (const entry of JSON.parse(fs.readFileSync(path.join(directory, file), "utf8"))) {
        if (!entry.url.startsWith("chrome-extension://") || !entry.source) continue;
        const name = new URL(entry.url).pathname.replace(/^\//, "");
        const script = scripts.get(name) || { source: entry.source, runs: [] };
        const ranges = [];
        for (const fn of entry.functions || []) {
            for (const range of fn.ranges || []) {
                ranges.push([range.startOffset, range.endOffset, range.count]);
            }
        }
        script.runs.push(ranges);
        scripts.set(name, script);
    }
}

function coveredBytes(script) {
    const combined = new Uint8Array(script.source.length);
    for (const ranges of script.runs) {
        const run = new Uint8Array(script.source.length);
        // V8 reports a positive outer function range with nested zero-count
        // ranges for blocks that were not taken. Apply broad ranges first so
        // the more-specific nested ranges override them.
        ranges.sort((left, right) =>
            (right[1] - right[0]) - (left[1] - left[0])
        );
        for (const [start, end, count] of ranges) {
            run.fill(count > 0 ? 1 : 0, start, end);
        }
        for (let index = 0; index < run.length; index++) {
            if (run[index]) combined[index] = 1;
        }
    }
    return combined.reduce((sum, value) => sum + value, 0);
}

let hit = 0;
let total = 0;
for (const [name, script] of [...scripts].sort()) {
    const covered = coveredBytes(script);
    hit += covered;
    total += script.source.length;
    console.log(`${name}: ${(100 * covered / script.source.length).toFixed(2)}% byte coverage`);
}
if (!scripts.has("content.js")) throw new Error("Playwright did not capture content.js coverage");
const percent = total ? 100 * hit / total : 0;
console.log(`Extension browser coverage: ${percent.toFixed(2)}% (${hit}/${total} bytes)`);
if (percent < 20) throw new Error(`Extension browser coverage ${percent.toFixed(2)}% is below 20%`);
