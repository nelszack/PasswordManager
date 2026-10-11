const { test, expect } = require("@playwright/test");
const http = require("node:http");

const { launchExtension, waitForNativeRequest } = require("./harness.cjs");

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

test("adds and updates credentials across username, password, and TOTP pages", async () => {
    test.skip(process.platform !== "linux", "The CI native-host fixture targets Chromium on Linux");

    const server = await startFixtureServer();
    const address = server.address();
    const origin = `http://127.0.0.1:${address.port}`;
    let browser;
    try {
        browser = await launchExtension();
        const { context, nativeLog } = browser;
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

        const save = await waitForNativeRequest(nativeLog, request => request.action === "saveCredentials");
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

        const update = await waitForNativeRequest(nativeLog, request => request.action === "updateCredentials");
        expect(update).toMatchObject({
            domain: origin,
            username: "alice@example.com",
            password: "changed-secret-password",
            entryId: 7
        });
    } finally {
        try { await browser?.close(); }
        finally { await new Promise(resolve => server.close(resolve)); }
    }
});
