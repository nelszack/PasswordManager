const { chromium, expect } = require("@playwright/test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const PROJECT_ROOT = path.resolve(__dirname, "../..");
const EXTENSION_PATH = path.join(PROJECT_ROOT, "extension");
const MOCK_HOST = path.join(__dirname, "native_host_mock.cjs");
const HOST_NAME = "com.myproject.password_manager";

function installNativeManifest(testHome, profile, extensionId, hostPath) {
    const manifest = JSON.stringify({
        name: HOST_NAME,
        description: "Password Manager end-to-end test host",
        path: hostPath,
        type: "stdio",
        allowed_origins: [`chrome-extension://${extensionId}/`]
    }, null, 2);
    const directories = [
        path.join(profile, "NativeMessagingHosts"),
        path.join(testHome, ".config", "chromium", "NativeMessagingHosts"),
        path.join(testHome, ".config", "google-chrome", "NativeMessagingHosts")
    ];
    for (const directory of directories) {
        fs.mkdirSync(directory, { recursive: true });
        fs.writeFileSync(path.join(directory, `${HOST_NAME}.json`), manifest);
    }
}

async function launchExtension(options = {}) {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pm-browser-e2e-"));
    const testHome = path.join(temporaryRoot, "home");
    const profile = path.join(temporaryRoot, "profile");
    const nativeLog = path.join(temporaryRoot, "native-messages.jsonl");
    fs.mkdirSync(testHome, { recursive: true });
    const context = await chromium.launchPersistentContext(profile, {
        headless: false,
        env: {
            ...process.env,
            HOME: testHome,
            XDG_CONFIG_HOME: path.join(testHome, ".config"),
            XDG_DATA_HOME: path.join(testHome, ".local", "share"),
            PM_E2E_NATIVE_LOG: nativeLog,
            PM_E2E_NATIVE_MODE: options.mode || "normal",
            PM_E2E_NATIVE_ACCOUNTS: JSON.stringify(options.accounts || []),
            ...(options.env || {})
        },
        args: [
            `--disable-extensions-except=${EXTENSION_PATH}`,
            `--load-extension=${EXTENSION_PATH}`
        ]
    });
    let worker = context.serviceWorkers()[0];
    if (!worker) worker = await context.waitForEvent("serviceworker");
    const extensionId = new URL(worker.url()).host;
    if (options.installHost !== false) {
        const hostPath = options.hostPath || MOCK_HOST;
        fs.chmodSync(hostPath, 0o755);
        installNativeManifest(testHome, profile, extensionId, hostPath);
    }
    return {
        context, extensionId, nativeLog, profile, temporaryRoot, testHome,
        async close() {
            await context.close();
            fs.rmSync(temporaryRoot, { recursive: true, force: true });
        }
    };
}

async function waitForNativeRequest(logPath, predicate) {
    let match = null;
    await expect.poll(() => {
        if (!fs.existsSync(logPath)) return null;
        match = fs.readFileSync(logPath, "utf8").trim().split("\n")
            .filter(Boolean).map(line => JSON.parse(line)).find(predicate) || null;
        return match;
    }).not.toBeNull();
    return match;
}

module.exports = {
    EXTENSION_PATH,
    HOST_NAME,
    installNativeManifest,
    launchExtension,
    waitForNativeRequest
};
