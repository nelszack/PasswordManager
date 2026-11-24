// The release extension contains runtime assets only, shared by all OS archives.
// `--browser firefox` writes the same assets with a generated Firefox manifest.
const fs = require("node:fs");
const path = require("node:path");
const { firefoxManifest } = require("./firefox_manifest.cjs");
const root = path.resolve(__dirname, "../extension");
const files = [
    "manifest.json", "background_runtime.js", "content_runtime.js", "common.css",
    "popup.html", "popup_runtime.js", "popup.css",
    "help.html", "help.css",
    "picker.html", "picker_runtime.js", "picker.css",
    "credential_prompt.html", "credential_prompt_runtime.js", "credential_prompt.css",
    "duo_prompt.html", "duo_prompt_runtime.js", "duo_prompt.css",
    "passkey_prompt.html", "passkey_prompt_runtime.js", "passkey_prompt.css",
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
        // In-page anchors ("#setup") and external links (https://…) are not files;
        // "help.html#setup" names help.html.
        for (const match of source.matchAll(/(?:src|href)=["']([^"'#][^"']*)["']/g)) {
            if (/^[a-z][a-z0-9+.-]*:/i.test(match[1])) continue;
            requireAsset(match[1].split("#")[0]);
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
const firefox = firefoxManifest(manifest);
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
