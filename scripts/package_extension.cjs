// The release extension contains runtime assets only, shared by all OS archives.
// `--browser firefox` writes the same assets with a generated Firefox manifest.
const fs = require("node:fs");
const path = require("node:path");
const { firefoxManifest } = require("./firefox_manifest.cjs");
const root = path.resolve(__dirname, "../extension");
const files = [
    "manifest.json", "background.js", "command_contract.js",
    "background_security.js", "background_state.js", "background_native.js",
    "background_status.js", "background_pending.js", "background_windows.js", "background_pickers.js",
    "background_prompts.js", "background_router.js", "background_duo.js", "background_passkeys.js",
    "native_protocol.js", "pending_credentials.js", "credential_prompt_state.js", "duo_detection.js",
    "content_runtime.js", "ui_transport.js", "ui_session.js", "common.css",
    "popup.html", "popup.js", "popup_state.js", "popup.css", "password_generator.js",
    "picker.html", "picker.js", "picker_state.js", "picker.css",
    "credential_prompt.html", "credential_prompt.js", "credential_prompt.css",
    "duo_prompt.html", "duo_prompt.js", "duo_prompt.css",
    "passkey_prompt.html", "passkey_prompt.js", "passkey_prompt.css",
    "webauthn_page.js", "webauthn_bridge.js",
    "icons/icon16.png", "icons/icon32.png", "icons/icon48.png", "icons/icon128.png"
];
const allowed = new Set(files);
function requireAsset(file) {
    if (!allowed.has(file)) throw new Error(`Runtime asset missing from release allowlist: ${file}`);
    if (!fs.statSync(path.join(root, file)).isFile()) throw new Error(`Missing runtime asset: ${file}`);
}
for (const file of files) {
    requireAsset(file);
    const source = fs.readFileSync(path.join(root, file), "utf8");
    if (file.endsWith(".html")) {
        for (const match of source.matchAll(/(?:src|href)=["']([^"']+)["']/g)) requireAsset(match[1]);
    }
    if (file.endsWith(".js")) {
        for (const call of source.matchAll(/importScripts\(([^)]+)\)/g)) {
            for (const match of call[1].matchAll(/["']([^"']+)["']/g)) requireAsset(match[1]);
        }
    }
}
const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
for (const file of [manifest.background.service_worker, manifest.action.default_popup,
    ...Object.values(manifest.icons), ...Object.values(manifest.action.default_icon),
    ...manifest.content_scripts.flatMap(script => [...script.js, ...(script.css || [])])]) requireAsset(file);
const args = process.argv.slice(2);
let browser = "chrome";
if (args[0] === "--browser") {
    browser = args[1];
    args.splice(0, 2);
}
const destination = args[0];
if (args.length !== 1 || !destination || !["chrome", "firefox"].includes(browser)) {
    throw new Error("Usage: node scripts/package_extension.cjs [--browser chrome|firefox] DESTINATION|--check");
}
const firefox = firefoxManifest(manifest, fs.readFileSync(path.join(root, "background.js"), "utf8"));
for (const file of firefox.background.scripts) requireAsset(file);
if (destination !== "--check") {
    const target = path.resolve(destination);
    // A fresh directory prevents development files from surviving an earlier copy.
    fs.mkdirSync(target);
    for (const file of files) {
        fs.mkdirSync(path.dirname(path.join(target, file)), { recursive: true });
        fs.copyFileSync(path.join(root, file), path.join(target, file));
    }
    if (browser === "firefox") {
        fs.writeFileSync(path.join(target, "manifest.json"), JSON.stringify(firefox, null, 2) + "\n");
    }
}
console.log(`Release extension (${browser}): ${files.length} runtime assets verified`);
