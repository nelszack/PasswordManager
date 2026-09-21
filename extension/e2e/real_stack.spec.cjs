const { test, expect } = require("@playwright/test");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const { installNativeManifest, launchExtension } = require("./harness.cjs");

const PM_BINARY = path.resolve(__dirname, "../../target/debug/pm");

function availablePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.once("error", reject);
        server.listen(0, "127.0.0.1", () => {
            const port = server.address().port;
            server.close(error => error ? reject(error) : resolve(port));
        });
    });
}

function startFixture() {
    const server = http.createServer((_request, response) => {
        response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        response.end(`<!doctype html><html><body>
            <form id="login"><input id="username" autocomplete="username">
            <input id="password" type="password" autocomplete="current-password">
            <button type="submit">Sign in</button></form>
            <script>login.onsubmit = event => event.preventDefault();</script>
        </body></html>`);
    });
    return new Promise(resolve => server.listen(0, "127.0.0.1", () => resolve(server)));
}

function runPm(environment, ...args) {
    return childProcess.execFileSync(PM_BINARY, args, {
        cwd: path.dirname(PM_BINARY),
        env: environment,
        encoding: "utf8",
        timeout: 15_000
    });
}

test("the extension saves through the real native host into a temporary vault", async () => {
    test.setTimeout(90_000);
    test.skip(process.platform !== "linux", "The CI browser integration runs on Linux");
    test.skip(!fs.existsSync(PM_BINARY), "Build target/debug/pm before running this integration test");

    const fixture = await startFixture();
    const origin = `http://127.0.0.1:${fixture.address().port}`;
    const browser = await launchExtension({ installHost: false });
    const port = await availablePort();
    const environment = {
        ...process.env,
        HOME: browser.testHome,
        XDG_CONFIG_HOME: path.join(browser.testHome, ".config"),
        XDG_DATA_HOME: path.join(browser.testHome, ".local", "share")
    };
    const keyPath = path.join(browser.temporaryRoot, "vault.key");
    const hostPath = path.join(browser.temporaryRoot, "pm-native-host");
    let serverStarted = false;

    try {
        runPm(environment, "config", "--server-port", String(port));
        runPm(environment, "start");
        serverStarted = true;
        runPm(environment, "new", "--key", keyPath);
        runPm(environment, "unlock", "--key", keyPath, "--timeout", "0");

        fs.symlinkSync(PM_BINARY, hostPath);
        installNativeManifest(
            browser.testHome, browser.profile, browser.extensionId, hostPath
        );

        const page = browser.context.pages()[0] || await browser.context.newPage();
        await page.goto(origin);
        await expect(page.getByRole("button", { name: "Choose saved credentials" }).first())
            .toBeVisible();
        await page.locator("#username").fill("real@example.com");
        await page.locator("#password").fill("real-native-password");
        const opened = browser.context.waitForEvent(
            "page", popup => popup.url().includes("credential_prompt.html")
        );
        await page.getByRole("button", { name: "Sign in" }).click();
        const prompt = await opened;
        await expect(prompt.locator("#credentials")).toBeVisible();
        await prompt.locator("#name").fill("Real Native Entry");
        await prompt.locator("#add").click();
        await expect.poll(() => prompt.isClosed()).toBe(true);

        const result = JSON.parse(runPm(
            environment, "--json", "get", "--entry-name", "Real Native Entry"
        ));
        expect(result.ok).toBe(true);
        expect(result.output).toContain("real@example.com");
        expect(result.output).toContain(origin);
        const secret = JSON.parse(runPm(
            environment, "--json", "get", "--entry-name", "Real Native Entry",
            "--password-only"
        ));
        expect(secret).toMatchObject({ ok: true, output: "real-native-password" });
    } finally {
        if (serverStarted) {
            try {
                runPm(environment, "kill");
            } catch (_error) {
                // Preserve the original test failure if the server already stopped.
            }
        }
        await browser.close();
        await new Promise(resolve => fixture.close(resolve));
    }
});
