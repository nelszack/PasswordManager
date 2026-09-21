const { test, expect } = require("@playwright/test");
const http = require("node:http");
const { launchExtension, waitForNativeRequest } = require("./harness.cjs");

function html(body, script = "") {
    return `<!doctype html><html><head><meta charset="utf-8"></head><body>${body}<script>${script}</script></body></html>`;
}

function fixture(pathname, port) {
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
    if (pathname === "/iframe-login") return html(`
        <form><input id="username" autocomplete="username">
        <input id="password" type="password" autocomplete="current-password"></form>`);
    if (pathname === "/iframe-same") return html(
        `<iframe id="loginFrame" src="/iframe-login" width="500" height="200"></iframe>`
    );
    if (pathname === "/iframe-cross") return html(
        `<iframe id="loginFrame" src="http://localhost:${port}/iframe-login" width="500" height="200"></iframe>`
    );
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

test("autofill, exact matches, TOTP, SPA, registration, duplicates, and frames", async () => {
    test.setTimeout(90_000);
    test.skip(process.platform !== "linux");
    const server = await startServer();
    const origin = `http://127.0.0.1:${server.address().port}`;
    const account = {
        id: 7, name: "Alice", username: "alice@example.com", password: "saved-password",
        has_totp: true, domain: origin
    };
    const secondAccount = {
        id: 8, name: "Bob", username: "bob@example.com", password: "bob-password",
        has_totp: false, domain: origin
    };
    const browser = await launchExtension({ accounts: [account, secondAccount] });
    const page = browser.context.pages()[0] || await browser.context.newPage();
    try {
        // Existing-credential picker fills the intended form.
        await page.goto(`${origin}/simple`);
        const picker = await openPicker(browser.context,
            page.getByRole("button", { name: "Choose saved credentials" }).first());
        await picker.getByRole("button", { name: /Alice/ }).click();
        await expect(page.locator("#username")).toHaveValue("alice@example.com");
        await expect(page.locator("#password")).toHaveValue("saved-password");

        // An exact match resumes submission without opening a save prompt.
        const pagesBefore = browser.context.pages().length;
        await page.locator("#submit").click();
        await expect(page.locator("body")).toHaveAttribute("data-submitted", "yes");
        await page.waitForTimeout(300);
        expect(browser.context.pages().length).toBe(pagesBefore);

        // With multiple accounts, the submitted username selects the update target.
        await page.reload();
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

        // TOTP is fetched only after the secure picker selection.
        await page.goto(`${origin}/totp`);
        const totpPicker = await openPicker(browser.context,
            page.getByRole("button", { name: "Choose authenticator code" }));
        await totpPicker.getByRole("button", { name: /Alice/ }).click();
        await expect(page.locator("#totp")).toHaveValue("123456");

        // A JavaScript-only username/password/TOTP transition opens one durable prompt.
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

        // Registration captures the primary new password, not its confirmation as a second login.
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

        // Click + submit behavior must still create only one popup.
        await page.goto(`${origin}/duplicate`);
        await page.locator("#username").fill("duplicate@example.com");
        await page.locator("#password").fill("duplicate-password");
        const duplicatePrompt = await openPrompt(browser.context, page.locator("#next"));
        await expect(duplicatePrompt.locator("#credentials")).toBeVisible();
        expect(browser.context.pages().filter(candidate =>
            candidate.url().includes("credential_prompt.html") && !candidate.isClosed()
        )).toHaveLength(1);
        await duplicatePrompt.locator("#cancel").click();

        // Same-origin frames may fill their own fields.
        await page.goto(`${origin}/iframe-same`);
        const sameFrame = page.frameLocator("#loginFrame");
        const framePicker = await openPicker(browser.context,
            sameFrame.getByRole("button", { name: "Choose saved credentials" }).first());
        await framePicker.getByRole("button", { name: /Alice/ }).click();
        await expect(sameFrame.locator("#username")).toHaveValue("alice@example.com");

        // A cross-origin frame cannot use credentials authorized for the top origin.
        await page.goto(`${origin}/iframe-cross`);
        const crossFrame = page.frameLocator("#loginFrame");
        const crossPicker = await openPicker(browser.context,
            crossFrame.getByRole("button", { name: "Choose saved credentials" }).first());
        await expect(crossPicker.locator("#status")).toHaveText("Not found.");
        await crossPicker.locator("#cancel").click();
    } finally {
        await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
});

test("native-host failures remain visible and never expose the form", async () => {
    test.setTimeout(90_000);
    test.skip(process.platform !== "linux");
    const server = await startServer();
    const origin = `http://127.0.0.1:${server.address().port}`;
    const cases = [
        { mode: "missing", installHost: false, message: /native messaging host not found/i },
        { mode: "locked", message: /vault is locked/i },
        { mode: "unavailable", message: /server is unavailable/i },
        { mode: "malformed", message: /invalid credential response/i },
        { mode: "timeout", message: /request timed out/i }
    ];
    try {
        for (const scenario of cases) {
            const browser = await launchExtension(scenario);
            try {
                const page = browser.context.pages()[0] || await browser.context.newPage();
                await page.goto(`${origin}/simple`);
                await expect(page.getByRole("button", { name: "Choose saved credentials" }).first()).toBeVisible();
                await page.locator("#username").fill("failure@example.com");
                await page.locator("#password").fill("failure-password");
                const prompt = await openPrompt(browser.context, page.locator("#submit"));
                await expect(prompt.locator("#status")).toHaveText(scenario.message, { timeout: 10_000 });
                await expect(prompt.locator("#credentials")).toBeHidden();
            } finally {
                await browser.close();
            }
        }
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
});
