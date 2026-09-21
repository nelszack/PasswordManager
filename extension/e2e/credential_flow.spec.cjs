const { test, expect, chromium } = require("@playwright/test");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");

const PROJECT_ROOT = path.resolve(__dirname, "../..");
const EXTENSION_PATH = path.join(PROJECT_ROOT, "extension");
const NATIVE_HOST = path.join(__dirname, "native_host_mock.cjs");
const HOST_NAME = "com.myproject.password_manager";

function pageHtml(step) {
    const fields = {
        username: `
            <label for="username">Username</label>
            <input id="username" name="username" autocomplete="username">
            <button id="next" type="button">Next</button>`,
        password: `
            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="current-password">
            <button id="next" type="button">Next</button>`,
        totp: `
            <label for="totp">Authenticator code</label>
            <input id="totp" name="totp" autocomplete="one-time-code">
            <button type="button">Verify</button>`
    };
    const next = step === "username" ? "/password" : "/totp";
    return `<!doctype html>
        <html><head><meta charset="utf-8"><title>${step}</title></head>
        <body><main>${fields[step]}</main>
        ${step === "totp" ? "" : `<script>
            document.getElementById("next").addEventListener("click", () => {
                window.location.assign(${JSON.stringify(next)});
            });
        </script>`}
        </body></html>`;
}

function startFixtureServer() {
    const server = http.createServer((request, response) => {
        const step = request.url === "/password"
            ? "password"
            : request.url === "/totp" ? "totp" : "username";
        response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        response.end(pageHtml(step));
    });
    return new Promise(resolve => {
        server.listen(0, "127.0.0.1", () => resolve(server));
    });
}

function installMockNativeHost(testHome, profile, extensionId) {
    fs.chmodSync(NATIVE_HOST, 0o755);
    const manifest = JSON.stringify({
        name: HOST_NAME,
        description: "Password Manager end-to-end test host",
        path: NATIVE_HOST,
        type: "stdio",
        allowed_origins: [`chrome-extension://${extensionId}/`]
    }, null, 2);
    // Playwright may use either its Chromium build or Chrome for Testing.
    const manifestDirectories = [
        path.join(profile, "NativeMessagingHosts"),
        ...["chromium", "google-chrome"].map(browserDirectory => path.join(
            testHome, ".config", browserDirectory, "NativeMessagingHosts"
        ))
    ];
    for (const manifestDirectory of manifestDirectories) {
        fs.mkdirSync(manifestDirectory, { recursive: true });
        fs.writeFileSync(path.join(manifestDirectory, `${HOST_NAME}.json`), manifest);
    }
}

async function waitForNativeAction(logPath, action) {
    await expect.poll(() => {
        if (!fs.existsSync(logPath)) return null;
        return fs.readFileSync(logPath, "utf8")
            .trim()
            .split("\n")
            .filter(Boolean)
            .map(line => JSON.parse(line))
            .find(request => request.action === action) || null;
    }).not.toBeNull();
    return fs.readFileSync(logPath, "utf8")
        .trim()
        .split("\n")
        .filter(Boolean)
        .map(line => JSON.parse(line))
        .find(request => request.action === action);
}

test("adds and updates credentials across username, password, and TOTP pages", async () => {
    test.skip(process.platform !== "linux", "The CI native-host fixture targets Chromium on Linux");

    const server = await startFixtureServer();
    const address = server.address();
    const origin = `http://127.0.0.1:${address.port}`;
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pm-browser-e2e-"));
    const testHome = path.join(temporaryRoot, "home");
    const profile = path.join(temporaryRoot, "profile");
    const nativeLog = path.join(temporaryRoot, "native-messages.jsonl");
    fs.mkdirSync(testHome, { recursive: true });

    let context = null;
    try {
        context = await chromium.launchPersistentContext(profile, {
            headless: false,
            env: {
                ...process.env,
                HOME: testHome,
                XDG_CONFIG_HOME: path.join(testHome, ".config"),
                PM_E2E_NATIVE_LOG: nativeLog
            },
            args: [
                `--disable-extensions-except=${EXTENSION_PATH}`,
                `--load-extension=${EXTENSION_PATH}`
            ]
        });

        let worker = context.serviceWorkers()[0];
        if (!worker) worker = await context.waitForEvent("serviceworker");
        const extensionId = new URL(worker.url()).host;
        installMockNativeHost(testHome, profile, extensionId);

        const page = context.pages()[0] || await context.newPage();
        await page.goto(`${origin}/username`);
        await expect(page.locator("#username")).toBeVisible();
        await expect(page.getByRole("button", { name: "Choose saved credentials" })).toBeVisible();
        await page.locator("#username").fill("alice@example.com");
        await Promise.all([
            page.waitForURL(`${origin}/password`),
            page.locator("#next").click()
        ]);
        await expect(page.getByRole("button", { name: "Choose saved credentials" })).toBeVisible();
        await page.locator("#password").fill("new-secret-password");
        const promptPromise = context.waitForEvent("page", candidate =>
            candidate.url().includes("credential_prompt.html")
        );
        await page.locator("#next").click();

        const prompt = await promptPromise;
        await expect(page).toHaveURL(`${origin}/totp`);
        await expect(page.locator("#totp")).toBeVisible();
        await expect(prompt.locator("#credentials")).toBeVisible();
        await expect(prompt.locator("#username")).toHaveValue("alice@example.com");
        await prompt.locator("#name").fill("End-to-end account");
        await prompt.locator("#add").click();
        await expect.poll(() => prompt.isClosed()).toBe(true);

        const save = await waitForNativeAction(nativeLog, "saveCredentials");
        expect(save).toMatchObject({
            domain: origin,
            username: "alice@example.com",
            password: "new-secret-password",
            name: "End-to-end account"
        });

        await page.goto(`${origin}/username`);
        await expect(page.getByRole("button", { name: "Choose saved credentials" })).toBeVisible();
        await page.locator("#username").fill("alice@example.com");
        await Promise.all([
            page.waitForURL(`${origin}/password`),
            page.locator("#next").click()
        ]);
        await expect(page.getByRole("button", { name: "Choose saved credentials" })).toBeVisible();
        await page.locator("#password").fill("changed-secret-password");
        const updatePromptPromise = context.waitForEvent("page", candidate =>
            candidate.url().includes("credential_prompt.html")
        );
        await page.locator("#next").click();

        const updatePrompt = await updatePromptPromise;
        await expect(updatePrompt.locator("#credentials")).toBeVisible();
        await expect(updatePrompt.locator("#username")).toHaveValue("alice@example.com");
        await expect(updatePrompt.locator("#update")).toHaveText("Update End-to-end account");
        await updatePrompt.locator("#update").click();
        await expect.poll(() => updatePrompt.isClosed()).toBe(true);

        const update = await waitForNativeAction(nativeLog, "updateCredentials");
        expect(update).toMatchObject({
            domain: origin,
            username: "alice@example.com",
            password: "changed-secret-password",
            entryId: 7
        });
    } finally {
        if (context) await context.close();
        await new Promise(resolve => server.close(resolve));
        fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
});
