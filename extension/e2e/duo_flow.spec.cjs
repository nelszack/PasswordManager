const { test, expect } = require("@playwright/test");
const fs = require("node:fs");
const { launchExtension, readNativeRequests, waitForNativeRequest } = require("./harness.cjs");
const origin = "https://login.example";
const challenge = "<!doctype html><html><body><h1>Duo Push</h1><p>Push sent. Check your phone.</p></body></html>";
const universalChallenge = '<!doctype html><html><body><h1>Check for a Duo Push</h1><p>Verify it\'s you by approving the notification...</p><p>Sent to "Password Manager"</p><button>Other options</button><p>Need help? Secured by Duo</p></body></html>';
const pending = options => ({ entryId: 7, id: "synthetic-request", application: "Example VPN", username: "alice@example.com",
    location: "Boise", summary: "Login", expires_at: Math.floor(Date.now() / 1000) + 300,
    fingerprint: "a".repeat(128), code_digits: null, unsupported: null, ...options });

async function setup(options = {}) {
    const browser = await launchExtension({ allowHttp: false, mode: options.mode, accounts: [
        { id: 7, name: "Work", username: "alice@example.com", password: "saved-secret", has_duo: true, domain: origin,
            duo_origin: options.issuer ? "https://api-test.duosecurity.com" : undefined }
    ], env: { PM_E2E_NATIVE_DUO_REQUESTS: JSON.stringify(options.noRequest ? [] : [pending(options.request)]),
        ...(options.error ? { PM_E2E_NATIVE_DUO_ERROR: options.error } : {}) } });
    await browser.context.route(`${origin}/**`, route => route.fulfill({ contentType: "text/html", body:
        new URL(route.request().url()).pathname === "/login"
            ? '<!doctype html><html><body><form><input id="username" autocomplete="username"><input id="password" type="password" autocomplete="current-password"></form></body></html>'
            : options.universal ? universalChallenge : challenge }));
    const page = browser.context.pages()[0] || await browser.context.newPage();
    return { browser, page };
}
function decisions(browser) {
    return readNativeRequests(browser.nativeLog).filter(r => r.action === "managerDuoRespond");
}

async function withBrowser(options, run) {
    const env = await setup(options);
    try { await run(env); }
    finally { await env.browser.close(); }
}
async function openDuoWindow(browser, page, url = `${origin}/duo`, sourceOrigin = origin) {
    const opened = browser.context.waitForEvent("page", p => p.url().includes("duo_prompt.html"));
    await page.goto(url);
    const popup = await opened;
    await expect(popup.getByRole("heading", { name: "Duo Push" })).toBeVisible();
    await expect(popup.locator("#requests")).toContainText("Example VPN");
    await expect(popup.locator("#requests")).toContainText("alice@example.com");
    await expect(popup.locator("#destination")).toContainText(sourceOrigin);
    expect(decisions(browser)).toEqual([]);
    return popup;
}

test("Duo decisions require one explicit click and the appropriate verification", async () => {
    test.setTimeout(120_000);
    for (const scenario of [
        { name: "ordinary approval", approve: true },
        { name: "BYU–Idaho Universal Prompt approval", approve: true, universal: true },
        { name: "ordinary denial", approve: false },
        { name: "verified approval", approve: true, request: { code_digits: 3 } },
        { name: "unsupported approval leaves denial available", approve: false, request: { unsupported: "Requires proximity verification" } }
    ]) await test.step(scenario.name, () => withBrowser(scenario, async ({ browser, page }) => {
        const popup = await openDuoWindow(browser, page);
        const dialogs = []; popup.on("dialog", dialog => { dialogs.push(dialog.message()); dialog.dismiss(); });
        if (scenario.request?.unsupported) await expect(popup.getByRole("button", { name: "Approve", exact: true })).toBeDisabled();
        if (scenario.request?.code_digits) {
            const code = popup.getByLabel("3-digit code shown on the login page");
            await expect(code).toHaveAttribute("type", "password");
            await popup.getByRole("button", { name: "Approve", exact: true }).click();
            await expect(popup.locator("#status")).toContainText("Enter the verification code");
            expect(decisions(browser)).toEqual([]);
            await code.fill("012");
        }
        await popup.getByRole("button", { name: scenario.approve ? "Approve" : "Deny", exact: true }).click();
        const response = await waitForNativeRequest(browser.nativeLog, r => r.action === "managerDuoRespond");
        expect(response).toMatchObject({ approve: scenario.approve, entryId: 7, requestId: "synthetic-request",
            fingerprint: "a".repeat(128), verificationCode: scenario.request?.code_digits ? "012" : "" });
        expect(dialogs).toEqual([]);
        await expect.poll(() => popup.isClosed()).toBe(true);
        expect(decisions(browser)).toHaveLength(1);
    }));
});

test("dismissed windows stay dismissed while the same request is pending", () => withBrowser({}, async ({ browser, page }) => {
    const popup = await openDuoWindow(browser, page);
    await popup.getByRole("button", { name: "Dismiss" }).click();
    await expect.poll(() => popup.isClosed()).toBe(true);
    const worker = browser.context.serviceWorkers()[0];
    const tabId = await worker.evaluate(async () => (await chrome.tabs.query({ url: "https://login.example/*" }))[0].id);
    await worker.evaluate(async id => {
        const [result] = await chrome.tabs.sendMessage(id, { action: "getDuoChallengeState" }).then(r => [r]);
        if (!result.active) throw new Error("challenge not active");
    }, tabId);
    // Wait for the next real content-script poll, rather than sending a privileged fake trigger.
    await expect.poll(() => fs.readFileSync(browser.nativeLog, "utf8").split("managerDuoRequests").length, { timeout: 10_000 }).toBeGreaterThan(3);
    expect(browser.context.pages().filter(p => p.url().includes("duo_prompt.html"))).toHaveLength(0);
    expect(decisions(browser)).toEqual([]);
}));

test("navigation and locking close Duo windows and remove typed codes", async () => {
    test.setTimeout(60_000);
    for (const action of ["navigate", "lock"]) await test.step(action,
        () => withBrowser({ request: { code_digits: 3 } }, async ({ browser, page }) => {
        const popup = await openDuoWindow(browser, page);
        await popup.getByLabel("3-digit code shown on the login page").fill("012");
        if (action === "navigate") await page.goto(`${origin}/login`);
        else {
            const controls = await browser.context.newPage();
            await controls.goto(`chrome-extension://${browser.extensionId}/popup.html`);
            await controls.getByRole("button", { name: "Lock Vault" }).click();
        }
        await expect.poll(() => popup.isClosed(), { timeout: 10_000 }).toBe(true);
        expect(decisions(browser)).toEqual([]);
    }));
});

test("embedded challenges and Duo redirects retain the original login site", async () => {
    test.setTimeout(120_000);
    for (const scenario of ["embedded frame", "selected-login redirect", "Universal Prompt redirect", "Universal Prompt without remembered login"]) await test.step(scenario,
        () => withBrowser({ issuer: scenario === "Universal Prompt without remembered login" }, async ({ browser, page }) => {
        await browser.context.route("https://api-test.duosecurity.com/**", route => route.fulfill({ contentType: "text/html",
            body: scenario.startsWith("Universal Prompt") ? universalChallenge
                : '<!doctype html><html><body><h1>Check your device</h1></body></html>' }));
        let url = `${origin}/embedded`;
        if (scenario === "embedded frame") {
            await browser.context.route(url, route => route.fulfill({ contentType: "text/html",
                body: '<!doctype html><html><body><iframe src="https://api-test.duosecurity.com/push"></iframe></body></html>' }));
        } else if (scenario === "Universal Prompt without remembered login") {
            url = "https://api-test.duosecurity.com/push";
        } else {
            await page.goto(`${origin}/login`);
            const picking = browser.context.waitForEvent("page", p => p.url().includes("picker.html"));
            await page.getByRole("button", { name: "Choose saved credentials" }).first().click();
            const picker = await picking;
            await picker.getByRole("button", { name: "Work" }).click();
            await expect(page.locator("#password")).toHaveValue("saved-secret");
            url = "https://api-test.duosecurity.com/push";
        }
        const sourceOrigin = scenario === "Universal Prompt without remembered login" ? "https://api-test.duosecurity.com" : origin;
        const popup = await openDuoWindow(browser, page, url, sourceOrigin);
        await expect(popup.locator("#destination")).toContainText("https://api-test.duosecurity.com");
        await popup.getByRole("button", { name: "Dismiss" }).click();
    }));
});

test("no request produces no automatic window", () => withBrowser({ noRequest: true }, async ({ browser, page }) => {
    await page.goto(`${origin}/duo`);
    await waitForNativeRequest(browser.nativeLog, r => r.action === "managerDuoRequests");
    expect(browser.context.pages().filter(p => p.url().includes("duo_prompt.html"))).toHaveLength(0);
    expect(decisions(browser)).toEqual([]);
}));

test("a failed decision displays its uncertain outcome without permitting another click", () => withBrowser({ error: "Duo decision timed out" }, async ({ browser, page }) => {
    const popup = await openDuoWindow(browser, page);
    await popup.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(popup.locator("#status")).toContainText("Check the login before retrying");
    await expect(popup.getByRole("button", { name: "Approve", exact: true })).toHaveCount(0);
    expect(decisions(browser)).toHaveLength(1);
    await popup.getByRole("button", { name: "Dismiss" }).click();
    await expect.poll(() => popup.isClosed()).toBe(true);
}));
