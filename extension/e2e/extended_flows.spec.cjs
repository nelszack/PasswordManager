const { test, expect } = require("@playwright/test");
const http = require("node:http");
const { launchExtension, waitForNativeRequest } = require("./harness.cjs");

function html(body, script = "") {
    return `<!doctype html><html><head><meta charset="utf-8"></head><body>${body}<script>${script}</script></body></html>`;
}

function fixture(pathname, port) {
    if (pathname === "/iframe-card") return html(`<form><input id="card" autocomplete="cc-number"></form>`);
    if (pathname === "/iframe-card-cross") return html(
        `<iframe id="cardFrame" src="http://localhost:${port}/iframe-card" width="500" height="200"></iframe>`
    );
    if (pathname === "/spa") return html(`
        <main><label>Username <input id="username" autocomplete="username"></label>
        <button id="next" type="button">Next</button></main>`, `
        next.onclick = () => { document.querySelector("main").innerHTML =
            '<label>Password <input id="password" type="password" autocomplete="current-password"></label><button id="passwordNext" type="button">Next</button>';
            passwordNext.onclick = () => { document.querySelector("main").innerHTML =
                '<label>Authenticator code <input id="totp" autocomplete="one-time-code"></label>'; };
        };`);
    if (pathname === "/registration") return html(`
        <form id="register"><input id="email" type="email" autocomplete="username">
        <input id="newPassword" type="password" autocomplete="new-password">
        <input id="confirmPassword" type="password" autocomplete="new-password" aria-label="Confirm password">
        <button type="submit">Register</button></form>`, `register.onsubmit = event => event.preventDefault();`);
    if (pathname === "/duplicate") return html(`
        <form id="login"><input id="username" autocomplete="username">
        <input id="password" type="password" autocomplete="current-password">
        <button id="next" type="submit">Next</button></form>`, `
        login.addEventListener("submit", event => { event.preventDefault();
            login.dispatchEvent(new Event("duplicate-attempt")); });`);
    if (pathname === "/totp") return html(`<input id="totp" autocomplete="one-time-code">`);
    if (pathname === "/changing-role") return html(`
        <form><label>Address <input id="changing" autocomplete="street-address"></label></form>`, `
        window.changeToLogin = () => {
            changing.autocomplete = "username";
            changing.setAttribute("aria-label", "Username");
            document.querySelector("form").insertAdjacentHTML(
                "beforeend", '<input type="password" autocomplete="current-password">'
            );
        };`);
    if (pathname === "/iframe-login") return html(`
        <form><input id="username" autocomplete="username">
        <input id="password" type="password" autocomplete="current-password"></form>`);
    if (pathname === "/iframe-same") return html(
        `<iframe id="loginFrame" src="/iframe-login" width="500" height="200"></iframe>`
    );
    if (pathname === "/iframe-cross") return html(
        `<iframe id="loginFrame" src="http://localhost:${port}/iframe-login" width="500" height="200"></iframe>`
    );
    if (pathname === "/dynamic-shadow") return html(`<div id="mount"></div>`, `
        setTimeout(() => {
            const host = document.createElement("section");
            host.id = "shadowHost";
            const root = host.attachShadow({ mode: "open" });
            root.innerHTML = '<form><input id="shadowUser" autocomplete="username"><input id="shadowPassword" type="password" autocomplete="current-password"></form>';
            mount.appendChild(host);
        }, 100);
    `);
    return html(`
        <form id="login"><input id="username" autocomplete="username">
        <input id="password" type="password" autocomplete="current-password">
        <button id="submit" type="submit">Sign in</button></form>`, `
        login.addEventListener("submit", event => { event.preventDefault(); document.body.dataset.submitted = "yes"; });`);
}

function startServer() {
    const server = http.createServer((request, response) => {
        const port = server.address().port;
        response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        response.end(fixture(new URL(request.url, "http://fixture").pathname, port));
    });
    return new Promise(resolve => server.listen(0, "127.0.0.1", () => resolve(server)));
}

async function openPicker(context, button) {
    const opened = context.waitForEvent("page", page => page.url().includes("picker.html"));
    await button.click();
    return opened;
}

async function openPrompt(context, button) {
    const opened = context.waitForEvent("page", page => page.url().includes("credential_prompt.html"));
    await button.click();
    return opened;
}

test.describe("extended credential flows", () => {
    test.describe.configure({ mode: "serial", timeout: 90_000 });
    let server;
    let origin;
    let browser;
    let page;

    test.beforeAll(async () => {
        test.skip(process.platform !== "linux");
        server = await startServer();
        origin = `http://127.0.0.1:${server.address().port}`;
        browser = await launchExtension({ env: {
            PM_E2E_NATIVE_AUTOFILL_ITEMS: JSON.stringify([
                { id: 9, name: "Test Visa", kind: "payment-card", primary_secret: "4111111111111111", custom_fields: [] }
            ])
        }, accounts: [
            { id: 7, name: "Alice", username: "alice@example.com", password: "saved-password", has_totp: true, domain: origin },
            { id: 8, name: "Bob", username: "bob@example.com", password: "bob-password", has_totp: false, domain: origin }
        ] });
        page = browser.context.pages()[0] || await browser.context.newPage();
    });

    test.afterAll(async () => {
        await browser?.close();
        if (server) await new Promise(resolve => server.close(resolve));
    });

    test.afterEach(async () => {
        // Save coverage before the next test navigates and V8 discards this
        // document's content-script execution contexts.
        if (page && !page.isClosed()) await browser.coverPage(page, true);
    });

    test("saved credentials fill the intended form", async () => {
        await page.goto(`${origin}/simple`);
        const picker = await openPicker(browser.context,
            page.getByRole("button", { name: "Choose saved credentials" }).first());
        await picker.getByRole("button", { name: /Alice/ }).click();
        await expect(page.locator("#username")).toHaveValue("alice@example.com");
        await expect(page.locator("#password")).toHaveValue("saved-password");
    });

    test("a changing input role replaces its picker instead of stacking controls", async () => {
        await page.goto(`${origin}/changing-role`);
        await expect(page.getByRole("button", { name: "Choose identity" })).toHaveCount(1);
        await page.evaluate(() => window.changeToLogin());
        await expect(page.getByRole("button", { name: "Choose identity" })).toHaveCount(0);
        await expect(page.getByRole("button", { name: "Choose saved credentials" })).toHaveCount(2);
    });

    test("an exact match resumes without a save prompt", async () => {
        await page.goto(`${origin}/simple`);
        const picker = await openPicker(browser.context,
            page.getByRole("button", { name: "Choose saved credentials" }).first());
        await picker.getByRole("button", { name: /Alice/ }).click();
        const promptsBefore = browser.context.pages().filter(candidate =>
            candidate.url().includes("credential_prompt.html") && !candidate.isClosed()
        ).length;
        await page.locator("#submit").click();
        await expect(page.locator("body")).toHaveAttribute("data-submitted", "yes");
        await page.waitForTimeout(300);
        expect(browser.context.pages().filter(candidate =>
            candidate.url().includes("credential_prompt.html") && !candidate.isClosed()
        )).toHaveLength(promptsBefore);
    });

    test("a submitted username selects the matching update target", async () => {
        await page.goto(`${origin}/simple`);
        await expect(page.getByRole("button", { name: "Choose saved credentials" }).first()).toBeVisible();
        await page.locator("#username").fill("alice@example.com");
        await page.locator("#password").fill("alice-updated-password");
        const accountUpdate = await openPrompt(browser.context, page.locator("#submit"));
        await expect(accountUpdate.locator("#update")).toHaveText("Update Alice");
        await accountUpdate.locator("#update").click();
        const updateRequest = await waitForNativeRequest(browser.nativeLog, request =>
            request.action === "updateCredentials" && request.password === "alice-updated-password"
        );
        expect(updateRequest.entryId).toBe(7);
    });

    test("TOTP is fetched only after secure picker selection", async () => {
        await page.goto(`${origin}/totp`);
        const totpPicker = await openPicker(browser.context,
            page.getByRole("button", { name: "Choose authenticator code" }));
        await totpPicker.getByRole("button", { name: /Alice/ }).click();
        await expect(page.locator("#totp")).toHaveValue("123456");
    });

    test("SPA credential transitions retain the captured username", async () => {
        await page.goto(`${origin}/spa`);
        await expect(page.getByRole("button", { name: "Choose saved credentials" })).toBeVisible();
        await page.locator("#username").fill("spa@example.com");
        await page.locator("#next").click();
        await expect(page.locator("#password")).toBeVisible();
        await page.locator("#password").fill("spa-password");
        const spaPrompt = await openPrompt(browser.context, page.locator("#passwordNext"));
        await expect(page.locator("#totp")).toBeVisible();
        await expect(spaPrompt.locator("#username")).toHaveValue("spa@example.com");
        await spaPrompt.locator("#cancel").click();
    });

    test("registration captures the primary password once", async () => {
        await page.goto(`${origin}/registration`);
        await page.locator("#email").fill("new@example.com");
        await page.locator("#newPassword").fill("registration-password");
        await page.locator("#confirmPassword").fill("registration-password");
        const registrationPrompt = await openPrompt(browser.context, page.getByRole("button", { name: "Register" }));
        await expect(registrationPrompt.locator("#username")).toHaveValue("new@example.com");
        await registrationPrompt.locator("#name").fill("Registration");
        await registrationPrompt.locator("#add").click();
        await waitForNativeRequest(browser.nativeLog, request =>
            request.action === "saveCredentials" && request.password === "registration-password"
        );
    });

    test("password generation fills matching registration fields", async () => {
        await page.goto(`${origin}/registration`);
        await page.getByRole("button", { name: "Generate a strong password" }).first().click();
        const generated = await page.locator("#newPassword").inputValue();
        expect(generated).toHaveLength(20);
        await expect(page.locator("#confirmPassword")).toHaveValue(generated);
        await page.locator("#newPassword").fill("");
        await page.locator("#confirmPassword").fill("");
    });

    test("click and submit handling creates one prompt", async () => {
        await page.goto(`${origin}/duplicate`);
        await page.locator("#username").fill("duplicate@example.com");
        await page.locator("#password").fill("duplicate-password");
        const duplicatePrompt = await openPrompt(browser.context, page.locator("#next"));
        await expect(duplicatePrompt.locator("#credentials")).toBeVisible();
        expect(browser.context.pages().filter(candidate =>
            candidate.url().includes("credential_prompt.html") && !candidate.isClosed()
        )).toHaveLength(1);
        await duplicatePrompt.locator("#cancel").click();
    });

    test("same-origin frames fill their own fields", async () => {
        await page.goto(`${origin}/iframe-same`);
        const sameFrame = page.frameLocator("#loginFrame");
        const framePicker = await openPicker(browser.context,
            sameFrame.getByRole("button", { name: "Choose saved credentials" }).first());
        await framePicker.getByRole("button", { name: /Alice/ }).click();
        await expect(sameFrame.locator("#username")).toHaveValue("alice@example.com");
    });

    test("cross-origin frames cannot reuse top-origin authorization", async () => {
        await page.goto(`${origin}/iframe-cross`);
        const crossFrame = page.frameLocator("#loginFrame");
        const crossPicker = await openPicker(browser.context,
            crossFrame.getByRole("button", { name: "Choose saved credentials" }).first());
        await expect(crossPicker.locator("#status")).toHaveText("Not found.");
        await crossPicker.locator("#cancel").click();
    });

    test("dynamically inserted open shadow roots receive credential controls", async () => {
        await page.goto(`${origin}/dynamic-shadow`);
        await expect(page.locator("#shadowHost")).toBeAttached();
        await expect(page.getByRole("button", { name: "Choose saved credentials" }).first()).toBeVisible();
    });

    test("cross-origin card autofill displays both sites and requires confirmation", async () => {
        await page.goto(`${origin}/iframe-card-cross`);
        const frame = page.frameLocator("#cardFrame");
        const picker = await openPicker(browser.context,
            frame.getByRole("button", { name: "Choose payment card" }));
        const embeddedOrigin = `http://localhost:${server.address().port}`;
        await expect(picker.locator("#destination")).toHaveText(`Fill on: ${embeddedOrigin}`);
        await expect(picker.locator("#crossOriginText")).toContainText(origin);
        await picker.getByRole("button", { name: "Test Visa" }).click();
        await expect(picker.locator("#status")).toContainText("Confirm");
        await expect(frame.locator("#card")).toHaveValue("");
        await picker.locator("#confirmCrossOrigin").check();
        await picker.getByRole("button", { name: "Test Visa" }).click();
        await expect(frame.locator("#card")).toHaveValue("4111111111111111");
    });

    test("popup and picker entry points render without leaking page state", async () => {
        const popup = await browser.context.newPage();
        await browser.coverPage(popup);
        await popup.goto(`chrome-extension://${browser.extensionId}/popup.html`);
        await expect(popup.locator("#statusText")).not.toBeEmpty();

        const picker = await browser.context.newPage();
        await browser.coverPage(picker);
        await picker.goto(`chrome-extension://${browser.extensionId}/picker.html`);
        await expect(picker.locator("#status")).toHaveText("Missing picker token");

        const prompt = await browser.context.newPage();
        await prompt.goto(`chrome-extension://${browser.extensionId}/credential_prompt.html`);
        await expect(prompt.locator("#status")).toHaveText("Missing credential prompt token");
        await browser.coverPage(prompt, true);
        await prompt.reload();
        await expect(prompt.locator("#status")).toHaveText("Missing credential prompt token");
        await expect(prompt.locator("#credentials")).toBeHidden();
    });

    test("a save prompt retains its metadata across reloading", async () => {
        await page.goto(`${origin}/simple`);
        await page.locator("#username").fill("reload@example.com");
        await page.locator("#password").fill("reload-password");
        const prompt = await openPrompt(browser.context, page.locator("#submit"));
        await expect(prompt.locator("#credentials")).toBeVisible();
        // A native popup may change renderer while its first profiler attaches.
        // Restart recording in the loaded extension document before the reload.
        await browser.coverPage(prompt, true);
        await prompt.reload();
        await expect(prompt.locator("#credentials")).toBeVisible();
        await expect(prompt.locator("#site")).toHaveText(origin);
        await expect(prompt.locator("#username")).toHaveValue("reload@example.com");
    });
});

test("production manifest does not inject credential controls after an HTTP downgrade", async () => {
    test.skip(process.platform !== "linux");
    const server = await startServer();
    const origin = `http://127.0.0.1:${server.address().port}`;
    const browser = await launchExtension({ allowHttp: false });
    try {
        const page = browser.context.pages()[0] || await browser.context.newPage();
        await page.goto(`${origin}/simple`);
        await expect(page.locator("#username")).toBeVisible();
        await expect(page.getByRole("button", { name: "Choose saved credentials" })).toHaveCount(0);
    } finally {
        await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
});

test.describe("native-host failures", () => {
    const cases = [
        { mode: "missing", installHost: false },
        { mode: "locked" },
        { mode: "unavailable" },
        { mode: "malformed" },
        { mode: "timeout" }
    ];

    for (const scenario of cases) {
        test(`${scenario.mode} does not open an automatic save prompt`, async () => {
            test.setTimeout(30_000);
            test.skip(process.platform !== "linux");
            const server = await startServer();
            const origin = `http://127.0.0.1:${server.address().port}`;
            const browser = await launchExtension(scenario);
            try {
                const page = browser.context.pages()[0] || await browser.context.newPage();
                await page.goto(`${origin}/simple`);
                await expect(page.getByRole("button", { name: "Choose saved credentials" }).first()).toBeVisible();
                await page.locator("#username").fill("failure@example.com");
                await page.locator("#password").fill("failure-password");
                const prompts = [];
                browser.context.on("page", popup => prompts.push(popup));
                await page.locator("#submit").click();
                await expect(page.locator("body")).toHaveAttribute("data-submitted", "yes", { timeout: 20_000 });
                expect(prompts).toHaveLength(0);
            } finally {
                await browser.close();
                await new Promise(resolve => server.close(resolve));
            }
        });
    }
});
