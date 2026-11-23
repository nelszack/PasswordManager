const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const { loadScript } = require("./test_harness.cjs");
const security = require("./background_security.js");
const Passkeys = require("./background_passkeys.js");

const EXTENSION = "abcdefghijklmnopabcdefghijklmnop";
const ORIGIN = "https://login.example.com";
const tick = () => new Promise(resolve => setImmediate(resolve));
const SESSION = "s".repeat(64);
// Service status replies: unlocked, and whether the vault can confirm it is you
// (a master password or passkey PIN) in the desktop app.
const unlocked = (data = {}) => ({ success: true, data: { locked: false, ...data }, sessionId: SESSION });
const confirmable = () => unlocked({ passkey_verification: true });
const alice = { id: 3, revision: 1, rp_id: "example.com", user_name: "alice", display_name: "alice" };

function environment({ responses = {}, tabUrl = ORIGIN + "/signin", windowFails = false } = {}) {
    const requests = [];
    const created = [];
    const removed = [];
    let nextWindow = 50;
    const chrome = {
        runtime: { id: EXTENSION, lastError: null, getURL: path => `chrome-extension://${EXTENSION}/${path}` },
        windows: {
            create(options, callback) {
                created.push(options);
                if (windowFails) {
                    chrome.runtime.lastError = { message: "no window" };
                    callback(undefined);
                    chrome.runtime.lastError = null;
                } else callback({ id: nextWindow++ });
            },
            remove(id, callback) {
                removed.push(id);
                callback?.();
            },
        },
        tabs: { get: async () => ({ url: tabUrl }) },
    };
    const nativeRequest = async (action, fields) => {
        requests.push({ action, fields });
        const response = responses[action];
        return typeof response === "function" ? response(fields) : response ?? { success: false, error: "unavailable" };
    };
    let token = 0;
    const service = Passkeys.create({
        chrome,
        security,
        nativeRequest,
        crypto: { randomUUID: () => `token-${++token}` },
        setTimeout: () => 0,
    });
    const sender = { tab: { id: 7 }, frameId: 0, documentId: "doc-1", origin: ORIGIN, url: ORIGIN + "/signin" };
    const prompt = { id: EXTENSION, url: chrome.runtime.getURL("passkey_prompt.html?token=x") };
    return { service, requests, created, removed, sender, prompt, chrome };
}

const registration = (changes = {}) =>
    JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: { id: "AQID", name: "alice", displayName: "Alice" },
        challenge: "CQk",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        ...changes,
    });
const signIn = (changes = {}) => JSON.stringify({ rpId: "example.com", challenge: "CQk", ...changes });
const credential = { id: "Bw", rawId: "Bw", type: "public-key", response: { clientDataJSON: "e30" }, clientExtensionResults: {} };

test("only top-level HTTPS documents with complete browser metadata may ask", async () => {
    const env = environment();
    const valid = { kind: "create", requestId: "r1", options: registration() };
    for (const [message, sender] of [
        [valid, { ...env.sender, frameId: 1 }],
        [valid, { ...env.sender, origin: "http://login.example.com" }],
        [valid, { ...env.sender, origin: "null" }],
        [valid, { ...env.sender, documentId: "" }],
        [valid, { ...env.sender, tab: undefined }],
        [{ ...valid, kind: "delete" }, env.sender],
        [{ ...valid, requestId: "x".repeat(65) }, env.sender],
        [{ ...valid, options: "{" }, env.sender],
        [{ ...valid, options: "[]" }, env.sender],
        [{ ...valid, options: "x".repeat(64 * 1024 + 1) }, env.sender],
        [undefined, env.sender],
    ]) {
        await assert.rejects(env.service.request(message, sender), /Invalid passkey request/);
    }
    assert.equal(env.requests.length, 0);
});

test("requests this vault cannot serve go back to the browser", async () => {
    const env = environment({
        responses: { getPasskeys: { success: true, data: [], sessionId: "s" }, status: { success: false, error: "Server not running" } },
    });
    for (const options of [
        registration({ pubKeyCredParams: [{ type: "public-key", alg: -257 }] }),
        registration({ authenticatorSelection: { authenticatorAttachment: "cross-platform" } }),
        registration({ extensions: { prf: {} } }),
        registration({ hints: ["security-key"] }),
        registration({ rp: { name: "No ID" } }),
    ]) {
        assert.deepEqual({ ...(await env.service.request({ kind: "create", requestId: "r", options }, env.sender)) }, { fallback: true });
    }
    assert.equal(env.requests.length, 0, "no native call for unsupported options");
    const get = { kind: "get", requestId: "r", options: signIn() };
    assert.equal((await env.service.request({ ...get, options: signIn({ extensions: { largeBlob: {} } }) }, env.sender)).fallback, true);
    assert.equal((await env.service.request(get, env.sender)).fallback, true, "no saved passkey for this site");
    assert.equal(
        (await env.service.request({ kind: "create", requestId: "r", options: registration() }, env.sender)).fallback,
        true,
        "service unavailable"
    );
    assert.deepEqual(env.requests.map(r => r.fields?.domain), [ORIGIN, undefined]);
});

test("registration needs the person's confirmation and uses the browser-reported origin", async () => {
    const env = environment({
        responses: {
            status: { success: true, data: { locked: false }, sessionId: "a".repeat(64) },
            createPasskey: fields => ({ success: true, data: credential, fields }),
        },
    });
    const result = env.service.request({ kind: "create", requestId: "r1", options: registration() }, env.sender);
    await tick();
    assert.equal(env.created.length, 1);
    assert.match(env.created[0].url, /passkey_prompt\.html\?token=token-1$/);
    await assert.rejects(Promise.resolve().then(() => env.service.data({ token: "token-1" }, env.sender)), /Invalid passkey prompt/);
    const data = env.service.data({ token: "token-1" }, env.prompt);
    assert.equal(data.origin, ORIGIN);
    assert.equal(data.rp, "example.com");
    assert.equal(data.user, "alice");
    assert.equal(data.locked, false);
    assert.deepEqual(
        { ...(await env.service.request({ kind: "create", requestId: "r2", options: registration() }, env.sender)) },
        { error: "NotAllowedError", message: "Another passkey request is waiting." }
    );
    assert.equal((await env.service.complete({ token: "token-1", selection: { action: "confirm" } }, env.prompt)).success, true);
    const outcome = await result;
    assert.equal(outcome.credential.id, "Bw");
    const create = env.requests.find(r => r.action === "createPasskey");
    assert.equal(create.fields.domain, ORIGIN);
    assert.equal(create.fields.expectedSession, "a".repeat(64));
    assert.equal(create.fields.passkeyRequest, registration());
    assert.deepEqual(env.removed, [50], "the prompt window closes");
    assert.throws(() => env.service.data({ token: "token-1" }, env.prompt), /expired/);
});

test("sign-in lists only this site's passkeys and signs with the chosen one", async () => {
    const choices = [
        { id: 3, revision: 2, rp_id: "example.com", user_name: "alice", display_name: "Alice" },
        { id: 4, revision: 5, rp_id: "example.com", user_name: "bob", display_name: "Bob" },
    ];
    const env = environment({
        responses: {
            getPasskeys: { success: true, data: choices, sessionId: "b".repeat(64) },
            getPasskeyAssertion: { success: true, data: credential },
        },
    });
    const result = env.service.request({ kind: "get", requestId: "r1", options: signIn() }, env.sender);
    await tick();
    const data = env.service.data({ token: "token-1" }, env.prompt);
    assert.deepEqual(
        data.choices.map(choice => ({ ...choice })),
        [
            { id: 3, userName: "alice", displayName: "Alice" },
            { id: 4, userName: "bob", displayName: "Bob" },
        ]
    );
    await assert.rejects(
        env.service.complete({ token: "token-1", selection: { action: "confirm", id: 99 } }, env.prompt),
        /Choose one/
    );
    await env.service.complete({ token: "token-1", selection: { action: "confirm", id: 4 } }, env.prompt);
    assert.equal((await result).credential.id, "Bw");
    const assertion = env.requests.find(r => r.action === "getPasskeyAssertion");
    assert.deepEqual(
        { ...assertion.fields },
        {
            domain: ORIGIN,
            entryId: 4,
            expectedRevision: 5,
            expectedSession: "b".repeat(64),
            passkeyRequest: signIn(),
        }
    );
});

test("declining, other providers, closing, cancelling, and invalidation each settle the request", async () => {
    const choices = [alice];
    const env = environment({ responses: { getPasskeys: { success: true, data: choices, sessionId: "s" } } });
    const start = id => {
        const pending = env.service.request({ kind: "get", requestId: id, options: signIn() }, env.sender);
        return tick().then(() => pending);
    };
    let pending = env.service.request({ kind: "get", requestId: "a", options: signIn() }, env.sender);
    await tick();
    await env.service.complete({ token: "token-1", selection: { action: "fallback" } }, env.prompt);
    assert.equal((await pending).fallback, true);
    pending = env.service.request({ kind: "get", requestId: "b", options: signIn() }, env.sender);
    await tick();
    await env.service.complete({ token: "token-2", selection: { action: "cancel" } }, env.prompt);
    assert.equal((await pending).error, "NotAllowedError");
    pending = env.service.request({ kind: "get", requestId: "c", options: signIn() }, env.sender);
    await tick();
    assert.equal(env.service.windowRemoved(52), true);
    assert.equal(env.service.windowRemoved(999), false);
    assert.equal((await pending).error, "NotAllowedError");
    pending = env.service.request({ kind: "get", requestId: "d", options: signIn() }, env.sender);
    await tick();
    env.service.cancel({ requestId: "d" }, { ...env.sender, documentId: "other-document" });
    env.service.cancel({ requestId: "d" }, env.sender);
    assert.equal((await pending).error, "AbortError");
    pending = env.service.request({ kind: "get", requestId: "e", options: signIn() }, env.sender);
    await tick();
    env.service.invalidate();
    assert.equal((await pending).error, "NotAllowedError");
    void start;
});

test("locked vaults, changed pages, failed operations, and missing windows are reported", async () => {
    const lockedResponses = { status: { success: true, data: { locked: true }, sessionId: null } };
    const locked = environment({ responses: lockedResponses });
    const pending = locked.service.request({ kind: "create", requestId: "r", options: registration() }, locked.sender);
    await tick();
    assert.equal(locked.service.data({ token: "token-1" }, locked.prompt).locked, true);
    await assert.rejects(locked.service.complete({ token: "token-1", selection: { action: "confirm" } }, locked.prompt), /Unlock/);
    // Still locked: a refresh keeps the locked state.
    assert.equal((await locked.service.data({ token: "token-1", refresh: true }, locked.prompt)).locked, true);
    locked.service.invalidate();
    await pending;

    const lockedGet = environment({ responses: { getPasskeys: { success: false, error: "Vault locked." } } });
    const lockedSignIn = lockedGet.service.request({ kind: "get", requestId: "r", options: signIn() }, lockedGet.sender);
    await tick();
    assert.equal(lockedGet.service.data({ token: "token-1" }, lockedGet.prompt).locked, true);
    lockedGet.service.invalidate();

    // Unlocking in the desktop app lets the open window continue.
    const unlockingResponses = { getPasskeys: { success: false, error: "Vault locked." } };
    const unlocking = environment({ responses: unlockingResponses });
    const waiting = unlocking.service.request({ kind: "get", requestId: "r", options: signIn() }, unlocking.sender);
    await tick();
    unlockingResponses.getPasskeys = {
        success: true,
        sessionId: "a".repeat(64),
        data: [{ id: 3, revision: 1, rp_id: "example.com", user_name: "alice", display_name: "Alice" }],
    };
    unlockingResponses.status = unlocked();
    const refreshed = await unlocking.service.data({ token: "token-1", refresh: true }, unlocking.prompt);
    assert.equal(refreshed.locked, false);
    assert.equal(refreshed.choices.length, 1);
    unlocking.service.invalidate();
    await waiting;
    await lockedSignIn;

    // Unlocked but no passkey for this site: the browser's own options take over.
    const emptyResponses = { getPasskeys: { success: false, error: "Vault locked." } };
    const empty = environment({ responses: emptyResponses });
    const none = empty.service.request({ kind: "get", requestId: "r", options: signIn() }, empty.sender);
    await tick();
    emptyResponses.getPasskeys = { success: true, sessionId: "a".repeat(64), data: [] };
    emptyResponses.status = unlocked();
    await empty.service.data({ token: "token-1", refresh: true }, empty.prompt);
    assert.equal(JSON.stringify(await none), JSON.stringify({ fallback: true }));

    const moved = environment({
        tabUrl: "https://other.example/",
        responses: { status: unlocked() },
    });
    const changed = moved.service.request({ kind: "create", requestId: "r", options: registration() }, moved.sender);
    await tick();
    await assert.rejects(moved.service.complete({ token: "token-1", selection: { action: "confirm" } }, moved.prompt), /page changed/);
    assert.equal((await changed).error, "NotAllowedError");

    const excluded = environment({
        responses: {
            status: unlocked(),
            createPasskey: { success: false, error: "Passkey request failed: CredentialExcluded" },
        },
    });
    const duplicate = excluded.service.request({ kind: "create", requestId: "r", options: registration() }, excluded.sender);
    await tick();
    assert.equal(
        (await excluded.service.complete({ token: "token-1", selection: { action: "confirm" } }, excluded.prompt)).success,
        false
    );
    assert.equal((await duplicate).error, "InvalidStateError");

    const failing = environment({
        responses: {
            status: unlocked(),
            createPasskey: { success: false },
        },
    });
    const failed = failing.service.request({ kind: "create", requestId: "r", options: registration() }, failing.sender);
    await tick();
    const reply = await failing.service.complete({ token: "token-1", selection: { action: "confirm" } }, failing.prompt);
    assert.equal(reply.error, "Passkey request failed");
    assert.equal((await failed).error, "NotAllowedError");

    const noWindow = environment({
        windowFails: true,
        responses: { status: unlocked() },
    });
    const opened = noWindow.service.request({ kind: "create", requestId: "r", options: registration() }, noWindow.sender);
    assert.equal((await opened).fallback, true);
});

test("the bridge relays only well-formed same-window requests and falls back on failure", async () => {
    const posted = [];
    const sent = [];
    let listener;
    let reply = message => ({ success: true, echoed: message.action });
    const window = {
        addEventListener: (type, handler) => (listener = handler),
        postMessage: data => posted.push(data),
    };
    const chrome = {
        runtime: {
            lastError: null,
            sendMessage(message, callback) {
                sent.push(message);
                if (reply === "throw") throw new Error("Extension context invalidated");
                if (reply === "lastError") {
                    chrome.runtime.lastError = { message: "closed" };
                    callback(undefined);
                    chrome.runtime.lastError = null;
                    return;
                }
                callback(reply(message));
            },
        },
    };
    window.window = window;
    const context = vm.createContext({ window, chrome, location: { origin: ORIGIN } });
    const self = vm.runInContext("window", context);
    loadScript("webauthn_bridge.js", context);
    assert.equal(posted[0].type, "ready");
    const id = "123e4567-e89b-12d3-a456-426614174000";
    const event = data => listener({ source: self, origin: ORIGIN, data: { channel: "pm-passkey", ...data } });
    event({ type: "hello" });
    assert.equal(posted.at(-1).type, "ready");
    for (const data of [
        { type: "request", id: "bad id", kind: "get", options: "{}" },
        { type: "request", id, kind: "delete", options: "{}" },
        { type: "request", id, kind: "get", options: 7 },
        { type: "request", id, kind: "get", options: "x".repeat(64 * 1024 + 1) },
        { type: "other", id },
    ])
        event(data);
    listener({ source: {}, origin: ORIGIN, data: { channel: "pm-passkey", type: "request", id, kind: "get", options: "{}" } });
    listener({ source: self, origin: "https://evil.test", data: { channel: "pm-passkey", type: "hello" } });
    listener({ source: self, origin: ORIGIN, data: null });
    assert.equal(sent.length, 0);
    event({ type: "request", id, kind: "get", options: "{}" });
    assert.deepEqual({ ...sent[0] }, { action: "passkeyRequest", requestId: id, kind: "get", options: "{}" });
    assert.equal(posted.at(-1).result.echoed, "passkeyRequest");
    for (const failure of ["lastError", "throw", () => null, () => ({ success: false, error: "Invalid passkey request" })]) {
        reply = failure;
        event({ type: "request", id, kind: "create", options: "{}" });
        assert.equal(posted.at(-1).result.fallback, true);
    }
    reply = () => ({ success: true });
    event({ type: "cancel", id });
    assert.equal(sent.at(-1).action, "cancelPasskeyRequest");
});

test("proof that it is you comes from the desktop app as a one-time token", async () => {
    const token = "a".repeat(64);
    let confirmations = 0;
    const env = environment({
        responses: {
            status: confirmable(),
            verifyPasskeyUser: () =>
                ++confirmations === 1
                    ? { success: false, error: "Refused in the desktop app." }
                    : { success: true, data: token },
            createPasskey: { success: true, data: credential },
        },
    });
    const required = registration({ authenticatorSelection: { userVerification: "required" } });
    const result = env.service.request({ kind: "create", requestId: "r", options: required }, env.sender);
    await tick();
    const data = env.service.data({ token: "token-1" }, env.prompt);
    assert.equal(data.verification, "required");
    assert.equal(data.canConfirm, true);
    await assert.rejects(
        env.service.complete({ token: "token-1", selection: { action: "confirm" } }, env.prompt),
        /requires you to confirm/
    );
    assert.equal(env.requests.some(r => r.action === "verifyPasskeyUser"), false);
    // A refusal in the desktop app leaves the window open to try again.
    const refused = await env.service.complete({ token: "token-1", selection: { action: "confirm", confirmInDesktop: true } }, env.prompt);
    assert.deepEqual({ ...refused }, { success: false, error: "Refused in the desktop app." });
    assert.equal(env.requests.some(r => r.action === "createPasskey"), false);
    await env.service.complete({ token: "token-1", selection: { action: "confirm", confirmInDesktop: true } }, env.prompt);
    assert.equal((await result).credential.id, "Bw");
    const ask = env.requests.find(r => r.action === "verifyPasskeyUser");
    assert.deepEqual({ ...ask.fields }, { domain: ORIGIN, expectedSession: SESSION });
    assert.equal(env.requests.find(r => r.action === "createPasskey").fields.verificationToken, token);

    // Without the checkbox, or when the site discourages it, nothing waits.
    for (const options of [registration(), registration({ authenticatorSelection: { userVerification: "discouraged" } })]) {
        const quiet = environment({
            responses: {
                status: confirmable(),
                createPasskey: { success: true, data: credential },
            },
        });
        const pending = quiet.service.request({ kind: "create", requestId: "r", options }, quiet.sender);
        await tick();
        const discouraged = options.includes("discouraged");
        await quiet.service.complete(
            { token: "token-1", selection: { action: "confirm", confirmInDesktop: discouraged } },
            quiet.prompt
        );
        await pending;
        assert.equal(quiet.requests.some(r => r.action === "verifyPasskeyUser"), false);
        assert.equal("verificationToken" in quiet.requests.find(r => r.action === "createPasskey").fields, false);
    }
});

test("cancelling while the desktop app is asked ends the request", async () => {
    let answer;
    const env = environment({
        responses: {
            status: confirmable(),
            verifyPasskeyUser: () => new Promise(resolve => (answer = resolve)),
        },
    });
    const result = env.service.request({ kind: "create", requestId: "r", options: registration() }, env.sender);
    await tick();
    const confirming = env.service.complete({ token: "token-1", selection: { action: "confirm", confirmInDesktop: true } }, env.prompt);
    await tick();
    await env.service.complete({ token: "token-1", selection: { action: "cancel" } }, env.prompt);
    assert.equal((await result).error, "NotAllowedError");
    answer({ success: true, data: "b".repeat(64) });
    assert.equal((await confirming).success, false);
    assert.equal(env.requests.some(r => r.action === "createPasskey"), false, "a late confirmation is not used");
});

test("vaults that cannot confirm still work for sites that do not require proof", async () => {
    const keyFile = unlocked();
    const env = environment({ responses: { status: keyFile, createPasskey: { success: true, data: credential } } });
    const preferred = env.service.request({ kind: "create", requestId: "r", options: registration() }, env.sender);
    await tick();
    assert.equal(env.service.data({ token: "token-1" }, env.prompt).canConfirm, false);
    await assert.rejects(
        env.service.complete({ token: "token-1", selection: { action: "confirm", confirmInDesktop: true } }, env.prompt),
        /cannot confirm/
    );
    await env.service.complete({ token: "token-1", selection: { action: "confirm" } }, env.prompt);
    assert.equal((await preferred).credential.id, "Bw", "presence alone still works");

    const strict = environment({ responses: { status: keyFile } });
    const required = registration({ authenticatorSelection: { userVerification: "required" } });
    strict.service.request({ kind: "create", requestId: "r", options: required }, strict.sender);
    await tick();
    await assert.rejects(
        strict.service.complete({ token: "token-1", selection: { action: "confirm", confirmInDesktop: true } }, strict.prompt),
        /passkey PIN/
    );
    assert.equal(strict.requests.some(r => ["verifyPasskeyUser", "createPasskey"].includes(r.action)), false);
    strict.service.invalidate();

    // Sign-in learns the same from the service status.
    const signInEnv = environment({
        responses: {
            getPasskeys: { success: true, data: [alice], sessionId: SESSION },
            status: confirmable(),
        },
    });
    signInEnv.service.request({ kind: "get", requestId: "r", options: signIn() }, signInEnv.sender);
    await tick();
    assert.equal(signInEnv.service.data({ token: "token-1" }, signInEnv.prompt).canConfirm, true);
    signInEnv.service.invalidate();
});
