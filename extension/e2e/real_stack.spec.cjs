const { test: base, expect } = require("@playwright/test");
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

async function captureRevealExpirations(manager) {
    await manager.evaluate(() => {
        window.revealExpirations = [];
        const schedule = window.setTimeout;
        window.setTimeout = (callback, delay, ...args) => {
            if (delay === 30_000) { window.revealExpirations.push(callback); return 0; }
            return schedule(callback, delay, ...args);
        };
    });
}

// Each test gets an isolated browser, native registration, server, and key vault.
// Teardown also runs if setup or an assertion fails.
const test = base.extend({
    realVault: async ({}, use) => {
        base.skip(process.platform !== "linux", "Real native-host integration runs on Linux");
        base.skip(!fs.existsSync(PM_BINARY), "Build target/debug/pm first");
        const fixture = await startFixture();
        let browser, environment, started = false;
        try {
            const origin = `http://127.0.0.1:${fixture.address().port}`;
            browser = await launchExtension({ installHost: false });
            const port = await availablePort();
            environment = {
                ...process.env,
                HOME: browser.testHome,
                XDG_CONFIG_HOME: path.join(browser.testHome, ".config"),
                XDG_DATA_HOME: path.join(browser.testHome, ".local", "share")
            };
            const keyPath = path.join(browser.temporaryRoot, "vault.key");
            const hostPath = path.join(browser.temporaryRoot, "pm-native-host");
            runPm(environment, "config", "--server-port", String(port));
            runPm(environment, "start"); started = true;
            runPm(environment, "new", "--key", keyPath);
            fs.symlinkSync(PM_BINARY, hostPath);
            installNativeManifest(browser.testHome, browser.profile, browser.extensionId, hostPath);
            const stop = () => { runPm(environment, "kill"); started = false; };
            await use({ browser, environment, origin, keyPath, stop });
        } finally {
            if (started) { try { runPm(environment, "kill"); } catch (_) {} }
            try { await browser?.close(); }
            finally { await new Promise(resolve => fixture.close(resolve)); }
        }
    }
});

test("the extension saves through the real native host into a temporary vault", async ({ realVault }) => {
    test.setTimeout(90_000);
    const { browser, environment, origin, keyPath, stop } = realVault;
    runPm(environment, "unlock", "--key", keyPath, "--timeout", "0");
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
    expect(result.data).toMatchObject({ username: "real@example.com", urls: expect.arrayContaining([origin]) });
    const secret = JSON.parse(runPm(
        environment, "--json", "get", "--entry-name", "Real Native Entry",
        "--password-only"
    ));
    expect(secret).toMatchObject({ ok: true, data: "real-native-password" });

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

    stop();
    await page.goto(origin);
    await expect(page.getByRole("button", { name: "Choose saved credentials" }).first()).toBeVisible();
    await page.locator("#username").fill("stopped@example.com");
    await page.locator("#password").fill("stopped-server-password");
    const automaticPrompts = [];
    browser.context.on("page", popup => automaticPrompts.push(popup));
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.locator("body")).toHaveAttribute("data-submitted", "yes");
    expect(automaticPrompts).toHaveLength(0);
});

test("vault manager edits a real vault, preserves hidden fields, and configures signup generation", async ({ realVault }) => {
    test.setTimeout(120_000);
    const { browser, environment, origin, keyPath } = realVault;
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
    await manager.locator("#kind").selectOption("secure-note");
    await expect(manager.locator("#secretMultiline")).toHaveValue("synthetic-manager-password");
    await expect(manager.locator("#password")).toHaveValue("");
    await manager.locator("#kind").selectOption("login");
    await expect(manager.locator("#password")).toHaveValue("synthetic-manager-password");
    await expect(manager.locator("#secretMultiline")).toHaveValue("");
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
    await captureRevealExpirations(manager);
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
    await manager.locator("#kind").selectOption("secure-note");
    await expect(manager.locator("#secretMultiline")).toHaveValue("synthetic-manager-password");
    await manager.evaluate(() => window.revealExpirations.shift()());
    await expect(manager.locator("#password")).toHaveValue("");
    await expect(manager.locator("#secretMultiline")).toHaveValue("");
    await manager.locator("#kind").selectOption("login");
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
    await manager.locator("#kind").selectOption("api-secret");
    await expect(manager.locator("#secretMultiline")).toBeVisible();
    await expect(manager.locator("#secretMultiline")).toHaveValue("synthetic note\nsecond line");
    await manager.locator("#editForm button:not([type='button'])").click();
    await expect(manager.locator("#editor")).toBeHidden();
    expect(runPm(environment, "get", "--entry-name", "Multiline note", "--password-only").trim()).toBe("synthetic note\nsecond line");
    await manager.locator("#items button").click(); await manager.locator("#reveal").click();
    await expect(manager.locator("#kind")).toHaveValue("api-secret");
    await expect(manager.locator("#secretMultiline")).toHaveValue("synthetic note\nsecond line");
    runPm(environment, "lock");
    await expect(manager.locator("#locked")).toBeVisible();
    await expect(manager.locator("#secretMultiline")).toHaveValue("");
});

test("manager preserves CRLF primary and custom fields across hidden and revealed edits", async ({ realVault }) => {
    test.setTimeout(90_000);
    const { browser, keyPath } = realVault;
    const manager = await browser.context.newPage();
    await manager.goto(`chrome-extension://${browser.extensionId}/manager.html`);
    await manager.locator("#keyPath").fill(keyPath);
    await manager.locator("#unlockForm button").click();
    await expect(manager.locator("#unlocked")).toBeVisible();
    const primary = "primary first\r\nprimary second\rlast";
    const plain = "public first\r\npublic second\rlast";
    const secret = "private first\r\nprivate second\rlast";
    await manager.evaluate(async ({ primary, plain, secret }) => {
        const send = (action, fields) => new Promise((resolve, reject) => chrome.runtime.sendMessage({ action, ...fields }, response => response.success ? resolve(response.data) : reject(new Error(response.error))));
        const { sessionId } = await chrome.runtime.sendMessage({ action: "getStatus" });
        await send("managerAdd", { expectedSession: sessionId, item: { name: "Multiline fields", kind: "secure-note", username: "", password: primary,
            notes: "stored notes\r\nsecond line", urls: [], fields: [{ name: "public", value: plain, secret: false }, { name: "private\r\nfield", value: secret, secret: true }] } });
    }, { primary, plain, secret });
    await manager.locator("#search").fill("Multiline");
    const open = async () => {
        await manager.locator("#items button").click();
        await expect(manager.locator("#editor")).toBeVisible();
    };
    const fields = manager.getByLabel("Field value", { exact: true });
    const save = async () => {
        await manager.locator("#editForm button:not([type='button'])").click();
        await expect(manager.locator("#editor")).toBeHidden();
    };
    const read = () => manager.evaluate(async () => {
        const send = (action, fields) => new Promise((resolve, reject) => chrome.runtime.sendMessage({ action, ...fields }, response => response.success ? resolve(response.data) : reject(new Error(response.error))));
        const result = await send("managerList", { query: "Multiline fields" });
        const { sessionId } = await chrome.runtime.sendMessage({ action: "getStatus" });
        return send("managerItem", { entryId: result.items[0].id, reveal: true, expectedSession: sessionId });
    });
    const assertStored = async () => {
        const item = await read();
        expect(item.password).toBe(primary);
        expect(item.fields.find(field => field.name === "public").value).toBe(plain);
        expect(item.fields.find(field => field.name === "private\r\nfield").value).toBe(secret);
    };
    await open();
    await expect(fields.nth(0)).toHaveValue("public first\npublic second\nlast");
    await expect(fields.nth(1)).toHaveValue("");
    await expect(manager.locator("#secretMultiline")).toHaveValue("");
    await expect(manager.locator("#notes")).toHaveValue("stored notes\nsecond line");
    await manager.locator("#name").fill("Renamed multiline fields");
    await save(); await open(); await assertStored();
    expect((await read()).notes).toBe("stored notes\r\nsecond line");

    await captureRevealExpirations(manager);
    await manager.locator("#reveal").click();
    await expect(fields.nth(1)).toHaveValue("private first\nprivate second\nlast");
    await expect(manager.locator("#secretMultiline")).toHaveValue("primary first\nprimary second\nlast");
    // The checkbox changes storage classification; textarea.type is read-only.
    await manager.locator(".custom-field input[type=checkbox]").nth(1).uncheck();
    await manager.locator(".custom-field input[type=checkbox]").nth(1).check();
    await manager.locator("#kind").selectOption("api-secret");
    await manager.locator("#notes").fill("Revealed values retain their stored line endings");
    await save(); await open(); await assertStored();
    await manager.locator("#reveal").click();
    await expect(fields.nth(1)).toHaveValue("private first\nprivate second\nlast");
    await manager.evaluate(() => window.revealExpirations.at(-1)());
    await expect(fields.nth(1)).toHaveValue("");
    await expect(manager.locator("#secretMultiline")).toHaveValue("");
    await manager.locator("#notes").fill("Expired reveals preserve hidden secrets");
    await save(); await open(); await assertStored();
    await manager.locator("#reveal").click();
    await expect(fields.nth(1)).toHaveValue("private first\nprivate second\nlast");
    await fields.nth(1).fill("edited\ncustom value");
    await save(); await open();
    const edited = await read();
    expect(edited.fields.find(field => field.name === "private\r\nfield").value).toBe("edited\ncustom value");
});

test("overlapping manager edits reject the stale revision instead of silently overwriting the first save", async ({ realVault }) => {
    test.setTimeout(90_000);
    const { browser, environment, keyPath } = realVault;
    const first = await browser.context.newPage();
    await first.goto(`chrome-extension://${browser.extensionId}/manager.html`);
    await first.locator("#keyPath").fill(keyPath);
    await first.locator("#unlockForm button").click();
    await expect(first.locator("#unlocked")).toBeVisible();
    await first.locator("#new").click();
    await first.locator("#name").fill("Concurrent item");
    await first.locator("#password").fill("original-secret");
    await first.locator("#editForm button:not([type='button'])").click();
    await expect(first.locator("#items button")).toHaveText(/Concurrent item/);
    const second = await browser.context.newPage();
    await second.goto(`chrome-extension://${browser.extensionId}/manager.html`);
    await expect(second.locator("#items button")).toHaveText(/Concurrent item/);
    await first.locator("#items button").click();
    await second.locator("#items button").click();
    await expect(first.locator("#editor")).toBeVisible();
    await expect(second.locator("#editor")).toBeVisible();
    await first.locator("#name").fill("First manager saved");
    await first.locator("#editForm button:not([type='button'])").click();
    await expect(first.locator("#editor")).toBeHidden();
    await second.locator("#name").fill("Stale manager overwrite");
    await second.locator("#editForm button:not([type='button'])").click();
    await expect(second.locator("#message")).toContainText(/revision|conflict|changed/i);
    await expect(second.locator("#editor")).toBeVisible();
    const result = JSON.parse(runPm(environment, "--json", "get", "--entry-name", "First manager saved"));
    expect(result.data.name).toBe("First manager saved");
});
