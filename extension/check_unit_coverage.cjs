const { spawnSync } = require("node:child_process");

const result = spawnSync(process.execPath, [
    "--experimental-test-coverage",
    "--test",
    "--test-coverage-include=extension/*.js",
    "--test-coverage-include-all",
    "--test-coverage-exclude=extension/content_runtime.js",
    "--test-coverage-exclude=extension/manager_runtime.js",
    "--test-coverage-lines=58",
    "--test-coverage-branches=78",
    "extension/*.test.js"
], {
    cwd: require("node:path").resolve(__dirname, ".."),
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1", FORCE_COLOR: "0" }
});

process.stdout.write(result.stdout);
process.stderr.write(result.stderr);
if (result.status !== 0) process.exit(result.status || 1);

const thresholds = {
    "background_native.js": [95, 85],
    "background_pending.js": [95, 85],
    "background_pickers.js": [85, 70],
    "background_prompts.js": [90, 65],
    "background_router.js": [70, 80],
    "background_status.js": [80, 75],
    "background_duo.js": [90, 75],
    "duo_detection.js": [95, 75],
    "background_security.js": [95, 90],
    "background_state.js": [100, 95],
    "content_detection.js": [80, 70],
    "content_fields.js": [90, 65],
    "credential_prompt.js": [80, 40],
    "credential_prompt_state.js": [90, 75],
    "form_submission.js": [95, 85],
    "native_protocol.js": [95, 85],
    "pending_credentials.js": [95, 85],
    "picker.js": [75, 50],
    "picker_state.js": [95, 90],
    "popup.js": [95, 80],
    "popup_state.js": [95, 90]
};

for (const [file, [minimumLines, minimumBranches]] of Object.entries(thresholds)) {
    const escaped = file.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const match = result.stdout.match(new RegExp(`${escaped}\\s+\\|\\s+([0-9.]+)\\s+\\|\\s+([0-9.]+)`));
    if (!match) throw new Error(`Coverage report did not include ${file}`);
    const lines = Number(match[1]);
    const branches = Number(match[2]);
    if (lines < minimumLines || branches < minimumBranches) {
        throw new Error(
            `${file} coverage ${lines}% lines/${branches}% branches is below `
            + `${minimumLines}%/${minimumBranches}%`
        );
    }
}
