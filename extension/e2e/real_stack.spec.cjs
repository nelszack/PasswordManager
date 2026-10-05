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
            <script>login.onsubmit = event => {
                event.preventDefault(); document.body.dataset.submitted = "yes";
            };</script>
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

        await page.locator("#username").fill("");
        await page.locator("#password").fill("");
        const pickerOpened = browser.context.waitForEvent(
            "page", popup => popup.url().includes("picker.html")
        );
        await page.getByRole("button", { name: "Choose saved credentials" }).first().click();
        const picker = await pickerOpened;
        await expect(picker.locator("#destination")).toHaveText(`Fill on: ${origin}`);
        await picker.getByRole("button", { name: /Real Native Entry/ }).click();
        await expect(page.locator("#username")).toHaveValue("real@example.com");
        await expect(page.locator("#password")).toHaveValue("real-native-password");

        const secondPickerOpened = browser.context.waitForEvent(
            "page", popup => popup.url().includes("picker.html")
        );
        await page.getByRole("button", { name: "Choose saved credentials" }).first().click();
        const secondPicker = await secondPickerOpened;
        await expect(secondPicker.getByRole("button", { name: /Real Native Entry/ })).toBeVisible();
        runPm(environment, "lock");
        await expect.poll(() => secondPicker.isClosed()).toBe(true);

        runPm(environment, "kill");
        serverStarted = false;
        await page.goto(origin);
        await expect(page.getByRole("button", { name: "Choose saved credentials" }).first()).toBeVisible();
        await page.locator("#username").fill("stopped@example.com");
        await page.locator("#password").fill("stopped-server-password");
        const automaticPrompts = [];
        browser.context.on("page", popup => automaticPrompts.push(popup));
        await page.getByRole("button", { name: "Sign in" }).click();
        await expect(page.locator("body")).toHaveAttribute("data-submitted", "yes");
        expect(automaticPrompts).toHaveLength(0);
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

test("vault manager edits a real vault, preserves hidden fields, and configures signup generation", async () => {
    test.setTimeout(60_000);
    test.setTimeout(120_000);
    test.skip(process.platform !== "linux", "Real native-host integration runs on Linux");
    test.skip(!fs.existsSync(PM_BINARY), "Build target/debug/pm first");
    const fixture = await startFixture();
    const origin = `http://127.0.0.1:${fixture.address().port}`;
    const browser = await launchExtension({ installHost: false });
    const port = await availablePort();
    const environment = { ...process.env, HOME: browser.testHome,
        XDG_CONFIG_HOME: path.join(browser.testHome, ".config"), XDG_DATA_HOME: path.join(browser.testHome, ".local", "share") };
    const keyPath = path.join(browser.temporaryRoot, "vault.key");
    const hostPath = path.join(browser.temporaryRoot, "pm-native-host");
    let started = false;
    try {
        runPm(environment, "config", "--server-port", String(port));
        runPm(environment, "start"); started = true;
        runPm(environment, "new", "--key", keyPath);
        fs.symlinkSync(PM_BINARY, hostPath);
        installNativeManifest(browser.testHome, browser.profile, browser.extensionId, hostPath);
        const manager = await browser.context.newPage();
        await manager.goto(`chrome-extension://${browser.extensionId}/manager.html`);
        await expect(manager.locator("#unlockForm")).toBeVisible();
        await manager.locator("#keyPath").fill(keyPath);
        await manager.locator("#unlockForm button").click();
        await expect(manager.locator("#unlocked")).toBeVisible();
        expect(await manager.locator("#keyPath").inputValue()).toBe("");
        await manager.locator("#new").click();
        await manager.locator("#name").fill("Managed account");
        await manager.locator("#username").fill("alice");
        await manager.locator("#password").fill("synthetic-manager-password");
        await manager.locator("#urls").fill(`${origin}\nhttps://alternate.example`);
        await manager.locator("#notes").fill("managed notes");
        await manager.locator("#addField").click();
        await manager.getByLabel("Field name", { exact: true }).fill("recovery code");
        await manager.getByLabel("Field value", { exact: true }).fill("synthetic-recovery");
        await manager.locator(".custom-field input[type=checkbox]").check();
        await manager.locator("#editForm button:not([type='button'])").click();
        await expect(manager.locator("#items button")).toHaveText(/Managed account/);
        await manager.locator("#items button").click();
        await expect(manager.locator("#name")).toHaveValue("Managed account");
        await expect(manager.locator("#password")).toHaveValue("");
        await expect(manager.getByLabel("Field value", { exact: true })).toHaveValue("");
        await manager.locator("#name").fill("Renamed account");
        await manager.locator("#urls").fill("https://replacement.example");
        await manager.locator("#editForm button:not([type='button'])").click();
        await expect(manager.locator("#items button")).toHaveText(/Renamed account/);
        expect(runPm(environment, "get", "--entry-name", "Renamed account", "--password-only").trim()).toBe("synthetic-manager-password");
        expect(runPm(environment, "get", "--entry-name", "Renamed account", "--field", "recovery code").trim()).toBe("synthetic-recovery");
        const exportPath = path.join(browser.temporaryRoot, "export.json");
        runPm(environment, "export", "--path", exportPath);
        const exported = JSON.parse(fs.readFileSync(exportPath, "utf8"));
        expect(exported.items[0].url).toBe("https://replacement.example");
        expect(exported.items[0].additional_urls).toEqual([]);
        await manager.locator("#items button").click();
        await manager.evaluate(() => {
            window.revealExpirations = [];
            const schedule = window.setTimeout;
            window.setTimeout = (callback, delay, ...args) => {
                if (delay === 30_000) { window.revealExpirations.push(callback); return 0; }
                return schedule(callback, delay, ...args);
            };
        });
        await manager.locator("#reveal").click();
        await expect(manager.locator("#password")).toHaveValue("synthetic-manager-password");
        await expect(manager.getByLabel("Field value", { exact: true })).toHaveValue("synthetic-recovery");
        await manager.locator("#password").fill("unsaved replacement");
        await manager.evaluate(() => window.revealExpirations.shift()());
        await expect(manager.locator("#password")).toHaveValue("unsaved replacement");
        await expect(manager.getByLabel("Field value", { exact: true })).toHaveValue("");
        await manager.locator("#password").fill("");
        await manager.locator("#reveal").click();
        await expect(manager.locator("#password")).toHaveValue("synthetic-manager-password");
        await manager.locator("#reveal").click();
        await manager.waitForFunction(() => window.revealExpirations.length === 2);
        await manager.evaluate(() => window.revealExpirations.shift()());
        await expect(manager.locator("#password")).toHaveValue("synthetic-manager-password");
        await manager.evaluate(() => window.revealExpirations.shift()());
        await expect(manager.locator("#password")).toHaveValue("");
        await expect(manager.getByLabel("Field value", { exact: true })).toHaveValue("");
        await manager.locator("#genLength").fill("31");
        await manager.locator("#genSymbols").uncheck();
        await manager.locator("#saveGenerator").click();
        await expect(manager.locator("#message")).toHaveText("Browser generator defaults saved.");
        const page = await browser.context.newPage(); await page.goto(origin);
        await page.setContent('<form><input id="newPassword" type="password" autocomplete="new-password"><input id="confirmPassword" type="password" autocomplete="new-password"></form>');
        await page.getByRole("button", { name: "Generate a strong password", exact: true }).first().click();
        const generated = await page.locator("#newPassword").inputValue();
        expect(generated).toMatch(/^[A-Za-z2-9]{31}$/);
        await expect(page.locator("#confirmPassword")).toHaveValue(generated);
        await manager.locator("#genMode").selectOption("passphrase");
        await manager.locator("#genWords").fill("7"); await manager.locator("#genSeparator").fill(".");
        await manager.locator("#saveGenerator").click();
        await expect(manager.locator("#message")).toHaveText("Browser generator defaults saved.");
        await page.getByRole("button", { name: "Generate a strong password", exact: true }).first().click();
        await expect(page.locator("#newPassword")).toHaveValue(/^[a-z]+(?:\.[a-z]+){6}$/);
        const site = "https://signup.example";
        await browser.context.route(`${site}/**`, route => route.fulfill({ contentType: "text/html", body: '<form><input id="sitePassword" type="password" autocomplete="new-password"></form>' }));
        const sitePage = await browser.context.newPage(); await sitePage.goto(`${site}/register`);
        await manager.locator("#genSite").fill(site); await manager.locator("#genMode").selectOption("password");
        await manager.locator("#genLength").fill("18"); await manager.locator("#genUppercase").uncheck(); await manager.locator("#genLowercase").uncheck();
        await manager.locator("#saveGenerator").click();
        await expect(manager.locator("#message")).toHaveText(`Generator settings saved for ${site}.`);
        await sitePage.getByRole("button", { name: "Generate a strong password", exact: true }).click();
        await expect(sitePage.locator("#sitePassword")).toHaveValue(/^[2-9]{18}$/);
        await page.getByRole("button", { name: "Generate a strong password", exact: true }).first().click();
        await expect(page.locator("#newPassword")).toHaveValue(/^[a-z]+(?:\.[a-z]+){6}$/);
        await manager.locator("#removeSiteGenerator").click();
        await expect(manager.locator("#message")).toHaveText(`Site override removed for ${site}.`);
        await sitePage.getByRole("button", { name: "Generate a strong password", exact: true }).click();
        await expect(sitePage.locator("#sitePassword")).toHaveValue(/^[a-z]+(?:\.[a-z]+){6}$/);
        await manager.locator("#lock").click();
        await expect(manager.locator("#locked")).toBeVisible();
        await expect(manager.locator("#password")).toHaveValue("");
        await expect(manager.locator("#fields")).toBeEmpty();
        await manager.locator("#keyPath").fill(keyPath); await manager.locator("#unlockForm button").click();
        await expect(manager.locator("#unlocked")).toBeVisible();
        await manager.locator("#items button").click();
        manager.once("dialog", dialog => dialog.accept());
        await manager.locator("#delete").click();
        await expect(manager.locator("#count")).toHaveText("0 items");
        expect(runPm(environment, "trash")).toContain("Renamed account");
        await manager.locator("#new").click(); await manager.locator("#name").fill("Multiline note");
        await manager.locator("#kind").selectOption("secure-note");
        await manager.locator("#secretMultiline").fill("synthetic note\nsecond line");
        await manager.locator("#editForm button:not([type='button'])").click();
        await expect(manager.locator("#items button")).toHaveText(/Multiline note/);
        expect(runPm(environment, "get", "--entry-name", "Multiline note", "--password-only").trim()).toBe("synthetic note\nsecond line");
        await manager.locator("#items button").click(); await manager.locator("#reveal").click();
        await expect(manager.locator("#secretMultiline")).toHaveValue("synthetic note\nsecond line");
        runPm(environment, "lock");
        await expect(manager.locator("#locked")).toBeVisible();
        await expect(manager.locator("#secretMultiline")).toHaveValue("");
    } finally {
        if (started) { try { runPm(environment, "kill"); } catch (_) {} }
        await browser.close(); await new Promise(resolve => fixture.close(resolve));
    }
});
