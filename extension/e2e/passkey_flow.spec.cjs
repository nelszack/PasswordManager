const { test, expect } = require("@playwright/test");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const https = require("node:https");
const net = require("node:net");
const path = require("node:path");
const { installNativeManifest, launchExtension } = require("./harness.cjs");

const PM_BINARY = path.resolve(__dirname, "../../target/debug/pm");
const HOST = "login.example.com";

function availablePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.once("error", reject);
        server.listen(0, "127.0.0.1", () => {
            const port = server.address().port;
            server.close(error => (error ? reject(error) : resolve(port)));
        });
    });
}

// The page registers and signs in, then verifies the assertion itself with
// WebCrypto against the public key from registration.
const PAGE = `<!doctype html><html><body>
<button id="register">Register</button><button id="signin">Sign in</button>
<script>
const b64 = buffer => btoa(String.fromCharCode(...new Uint8Array(buffer)));
function rawSignature(der) {
    const bytes = new Uint8Array(der);
    let offset = 2;
    const part = () => {
        const length = bytes[offset + 1];
        let value = bytes.slice(offset + 2, offset + 2 + length);
        offset += 2 + length;
        while (value.length > 32 && value[0] === 0) value = value.slice(1);
        const padded = new Uint8Array(32);
        padded.set(value, 32 - value.length);
        return padded;
    };
    const r = part(), s = part();
    const out = new Uint8Array(64);
    out.set(r); out.set(s, 32);
    return out;
}
let publicKey, credentialId;
register.onclick = async () => {
    try {
        const credential = await navigator.credentials.create({ publicKey: {
            rp: { id: "example.com", name: "Example" },
            user: { id: new Uint8Array([1, 2, 3]), name: "alice@example.com", displayName: "Alice" },
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        } });
        publicKey = credential.response.getPublicKey();
        credentialId = credential.rawId;
        const client = JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON));
        const flags = new Uint8Array(credential.response.getAuthenticatorData())[32];
        document.body.dataset.registered = [credential instanceof PublicKeyCredential, client.type, client.origin, "uv=" + ((flags & 4) >> 2)].join(" ");
    } catch (error) { document.body.dataset.registered = "error " + error.name; }
};
signin.onclick = async () => {
    try {
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const credential = await navigator.credentials.get({ publicKey: {
            rpId: "example.com", challenge, allowCredentials: [{ type: "public-key", id: credentialId }],
        } });
        const r = credential.response;
        const client = JSON.parse(new TextDecoder().decode(r.clientDataJSON));
        const hash = await crypto.subtle.digest("SHA-256", r.clientDataJSON);
        const signed = new Uint8Array([...new Uint8Array(r.authenticatorData), ...new Uint8Array(hash)]);
        const key = await crypto.subtle.importKey("spki", publicKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
        const valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, rawSignature(r.signature), signed);
        const expected = b64(challenge).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
        document.body.dataset.signedIn = [valid, client.type, client.challenge === expected, new TextDecoder().decode(r.userHandle) === "\\u0001\\u0002\\u0003"].join(" ");
    } catch (error) { document.body.dataset.signedIn = "error " + error.name; }
};
</script></body></html>`;

// A real native host, vault and HTTPS page; `unlock` creates and unlocks the vault.
async function withPasskeySite(unlock, run) {
    const root = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "pm-passkey-e2e-"));
    childProcess.execFileSync("openssl", [
        "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
        "-keyout", path.join(root, "key.pem"), "-out", path.join(root, "cert.pem"),
        "-subj", `/CN=${HOST}`, "-addext", `subjectAltName=DNS:${HOST}`,
    ], { stdio: "ignore" });
    const server = https.createServer(
        { key: fs.readFileSync(path.join(root, "key.pem")), cert: fs.readFileSync(path.join(root, "cert.pem")) },
        (_request, response) => {
            response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
            response.end(PAGE);
        }
    );
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    const origin = `https://${HOST}:${server.address().port}`;
    let browser, environment, started = false;
    const runPm = (...args) => childProcess.execFileSync(PM_BINARY, args, { env: environment, encoding: "utf8", timeout: 15_000 });
    try {
        browser = await launchExtension({
            installHost: false,
            ignoreHTTPSErrors: true,
            args: [`--host-resolver-rules=MAP ${HOST} 127.0.0.1`],
        });
        environment = {
            ...process.env,
            HOME: browser.testHome,
            XDG_CONFIG_HOME: path.join(browser.testHome, ".config"),
            XDG_DATA_HOME: path.join(browser.testHome, ".local", "share"),
        };
        const hostPath = path.join(browser.temporaryRoot, "pm-native-host");
        runPm("config", "--server-port", String(await availablePort()));
        runPm("start"); started = true;
        await unlock({ runPm, environment, root: browser.temporaryRoot });
        fs.symlinkSync(PM_BINARY, hostPath);
        installNativeManifest(browser.testHome, browser.profile, browser.extensionId, hostPath);
        const page = browser.context.pages()[0] || await browser.context.newPage();
        await page.goto(origin);
        await run({ browser, page, origin, runPm, environment, port: server.address().port });
    } finally {
        if (started) { try { runPm("kill"); } catch (_) {} }
        try { await browser?.close(); }
        finally {
            await new Promise(resolve => server.close(resolve));
            fs.rmSync(root, { recursive: true, force: true });
        }
    }
}

function realStack() {
    test.skip(process.platform !== "linux", "Real native-host integration runs on Linux");
    test.skip(!fs.existsSync(PM_BINARY), "Build target/debug/pm first");
    test.setTimeout(90_000);
}

test("passkeys register and sign in through the real native host and vault", async () => {
    realStack();
    await withPasskeySite(({ runPm, root }) => {
        const keyPath = path.join(root, "vault.key");
        runPm("new", "--locked", "--key", keyPath);
        runPm("unlock", "--key", keyPath, "--timeout", "0");
    }, async ({ browser, page, origin, runPm, port }) => {
        let opened = browser.context.waitForEvent("page", popup => popup.url().includes("passkey_prompt.html"));
        await page.locator("#register").click();
        let prompt = await opened;
        await expect(prompt.locator("#destination")).toContainText(`${HOST}:${port}`);
        await expect(prompt.locator("#destination")).toContainText("alice@example.com");
        // A key-file vault without a passkey PIN cannot offer proof.
        await expect(prompt.locator("#verify")).toBeHidden();
        await prompt.getByRole("button", { name: "Save passkey" }).click();
        // Nobody confirmed, so the vault must not claim user verification.
        await expect(page.locator("body")).toHaveAttribute("data-registered", `true webauthn.create ${origin} uv=0`);
        const items = JSON.parse(runPm("--json", "view")).data.items;
        expect(items.some(item => item.name.startsWith("Passkey: example.com (alice@example.com)"))).toBe(true);

        opened = browser.context.waitForEvent("page", popup => popup.url().includes("passkey_prompt.html"));
        await page.locator("#signin").click();
        prompt = await opened;
        await expect(prompt.locator("#choices")).toContainText("Alice (alice@example.com)");
        await prompt.getByRole("button", { name: "Sign in" }).click();
        await expect(page.locator("body")).toHaveAttribute("data-signed-in", "true webauthn.get true true");

        // Declining returns the request to the browser; Chromium then fails it
        // (no authenticator is available in this test browser).
        opened = browser.context.waitForEvent("page", popup => popup.url().includes("passkey_prompt.html"));
        await page.locator("#signin").click();
        prompt = await opened;
        await prompt.getByRole("button", { name: "Cancel" }).click();
        await expect(page.locator("body")).toHaveAttribute("data-signed-in", "error NotAllowedError");
    });
});

// The CLI reads secrets from a terminal; `script` provides one.
function terminal(environment, command, answers) {
    const input = answers.map(answer => `sleep 1; printf '%s\\n' '${answer}'`).join("; ");
    return new Promise(resolve =>
        childProcess.execFile("sh", ["-c", `(${input}; sleep 2) | script -qec '${command}' /dev/null`], {
            env: environment, timeout: 30_000, encoding: "utf8",
        }, (error, stdout) => resolve({ ok: !error, output: stdout }))
    );
}

// Answers the waiting request the way the desktop app's banner does.
async function confirmInDesktop(runPm, environment, secret) {
    let id;
    await expect.poll(() => (id = runPm("status").match(/Passkey request ([0-9a-f]{12})/)?.[1]), { timeout: 15_000 })
        .toBeTruthy();
    return terminal(environment, `${PM_BINARY} passkey approve ${id}`, [secret]);
}

async function registerWithProof(browser, page) {
    const opened = browser.context.waitForEvent("page", popup => popup.url().includes("passkey_prompt.html"));
    await page.locator("#register").click();
    const prompt = await opened;
    await expect(prompt.locator("#verify")).toBeVisible();
    await expect(prompt.locator("#password")).toHaveCount(0);
    await prompt.locator("#confirmInDesktop").check();
    await prompt.getByRole("button", { name: "Save passkey" }).click();
    await expect(prompt.locator("#status")).toContainText("desktop app");
    return prompt;
}

const hasScript = () => childProcess.spawnSync("script", ["--version"]).status === 0;

test("confirming with the master password in the desktop makes the site see a verified user", async () => {
    realStack();
    test.skip(!hasScript(), "needs util-linux script");
    const master = "Synthetic-Passkey-Master-42";
    await withPasskeySite(async ({ environment, runPm }) => {
        await terminal(environment, `${PM_BINARY} new`, [master, master]);
        await terminal(environment, `${PM_BINARY} unlock --timeout 0`, [master]);
        expect(runPm("status")).toContain("Unlocked");
    }, async ({ browser, page, origin, runPm, environment }) => {
        const prompt = await registerWithProof(browser, page);
        // A wrong password is refused and the request keeps waiting.
        const wrong = await confirmInDesktop(runPm, environment, "not-the-master-password");
        expect(wrong.output).toContain("incorrect");
        const right = await confirmInDesktop(runPm, environment, master);
        expect(right.ok).toBe(true);
        await expect(page.locator("body")).toHaveAttribute("data-registered", `true webauthn.create ${origin} uv=1`);
        await expect.poll(() => prompt.isClosed()).toBe(true);
    });
});

test("a key-file vault confirms with this device's passkey PIN", async () => {
    realStack();
    test.skip(!hasScript(), "needs util-linux script");
    const pin = "864213";
    await withPasskeySite(async ({ runPm, root, environment }) => {
        const keyPath = path.join(root, "vault.key");
        runPm("new", "--locked", "--key", keyPath);
        runPm("unlock", "--key", keyPath, "--timeout", "0");
        expect((await terminal(environment, `${PM_BINARY} passkey set-pin`, [pin, pin])).output).toContain("Passkey PIN set");
    }, async ({ browser, page, origin, runPm, environment }) => {
        await registerWithProof(browser, page);
        expect((await confirmInDesktop(runPm, environment, pin)).ok).toBe(true);
        await expect(page.locator("body")).toHaveAttribute("data-registered", `true webauthn.create ${origin} uv=1`);
    });
});
