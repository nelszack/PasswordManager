const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const { loadScript } = require("./test_harness.cjs");

const ORIGIN = "https://login.example.com";
const b64 = bytes => Buffer.from(bytes).toString("base64url");

// A page world with WebAuthn, where the "extension" answers each request.
function page({ answer = () => ({ fallback: true }), ready = true, immediateTimers = false } = {}) {
    const posted = [];
    const original = [];
    let listener;
    class PublicKeyCredential {}
    class AuthenticatorAttestationResponse {}
    class AuthenticatorAssertionResponse {}
    const window = {
        location: { origin: ORIGIN, hostname: "login.example.com" },
        navigator: {
            credentials: {
                create: async options => (original.push(["create", options]), "native-create"),
                get: async options => (original.push(["get", options]), "native-get"),
            },
        },
        PublicKeyCredential,
        AuthenticatorAttestationResponse,
        AuthenticatorAssertionResponse,
        DOMException,
        btoa,
        atob,
        crypto: { randomUUID: () => "123e4567-e89b-12d3-a456-426614174000" },
        setTimeout: immediateTimers ? callback => callback() : setTimeout,
        addEventListener(type, handler) {
            if (type === "message") listener = handler;
        },
        postMessage(data, targetOrigin) {
            posted.push({ data, targetOrigin });
            queueMicrotask(() => {
                if (data.type === "request") {
                    const result = answer(data);
                    listener({ source: self, origin: ORIGIN, data: { channel: "pm-passkey", type: "result", id: data.id, result } });
                }
            });
        },
    };
    window.window = window;
    const context = vm.createContext(window);
    // Inside the context, `window` is the context's global object.
    const self = vm.runInContext("globalThis", context);
    loadScript("webauthn_page.js", context);
    if (ready) listener({ source: self, origin: ORIGIN, data: { channel: "pm-passkey", type: "ready" } });
    return { window, self, posted, original, deliver: event => listener(event) };
}

const creation = () => ({
    publicKey: {
        rp: { name: "Example" },
        user: { id: new Uint8Array([1, 2, 3]), name: "alice", displayName: "" },
        challenge: new Uint8Array([9, 9]).buffer,
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        excludeCredentials: [{ type: "public-key", id: new Uint8Array([7]), transports: ["internal"] }],
        authenticatorSelection: { residentKey: "required" },
        extensions: { credProps: true },
    },
});

test("registration requests become WebAuthn JSON and results become real-looking credentials", async () => {
    let sent;
    const env = page({
        answer: data => {
            sent = data;
            return {
                credential: {
                    id: "AQID",
                    rawId: "AQID",
                    type: "public-key",
                    authenticatorAttachment: "platform",
                    clientExtensionResults: { credProps: { rk: true } },
                    response: {
                        clientDataJSON: b64([123]),
                        attestationObject: b64([1]),
                        transports: ["internal"],
                        authenticatorData: b64([2]),
                        publicKey: b64([3]),
                        publicKeyAlgorithm: -7,
                    },
                },
            };
        },
    });
    assert.equal(env.posted[0].data.type, "hello");
    const credential = await env.window.navigator.credentials.create(creation());
    const options = JSON.parse(sent.options);
    assert.equal(sent.kind, "create");
    assert.equal(options.rp.id, "login.example.com", "the RP ID defaults to the page host");
    assert.equal(options.user.id, "AQID");
    assert.equal(options.user.displayName, "alice");
    assert.equal(options.challenge, "CQk");
    assert.deepEqual(options.excludeCredentials, [{ type: "public-key", id: "Bw", transports: ["internal"] }]);
    assert.deepEqual(options.extensions, { credProps: true });
    assert.ok(credential instanceof env.window.PublicKeyCredential);
    assert.ok(credential.response instanceof env.window.AuthenticatorAttestationResponse);
    assert.deepEqual([...new Uint8Array(credential.rawId)], [1, 2, 3]);
    assert.deepEqual([...new Uint8Array(credential.response.clientDataJSON)], [123]);
    assert.deepEqual([...new Uint8Array(credential.response.getPublicKey())], [3]);
    assert.deepEqual([...new Uint8Array(credential.response.getAuthenticatorData())], [2]);
    assert.equal(credential.response.getPublicKeyAlgorithm(), -7);
    assert.deepEqual([...credential.response.getTransports()], ["internal"]);
    assert.deepEqual(JSON.parse(JSON.stringify(credential.getClientExtensionResults())), { credProps: { rk: true } });
    assert.equal(credential.toJSON().id, "AQID");
    assert.equal(env.original.length, 0, "the browser's own WebAuthn was not used");
    assert.ok(env.posted.every(message => message.targetOrigin === ORIGIN));
});

test("sign-in requests carry the RP ID and allow list and return assertions", async () => {
    let sent;
    const env = page({
        answer: data => {
            sent = data;
            return {
                credential: {
                    id: "Bw",
                    rawId: "Bw",
                    type: "public-key",
                    response: { clientDataJSON: b64([1]), authenticatorData: b64([2]), signature: b64([3]), userHandle: b64([4]) },
                },
            };
        },
    });
    const credential = await env.window.navigator.credentials.get({
        publicKey: {
            challenge: new Uint8Array([5]),
            rpId: "example.com",
            allowCredentials: [{ type: "public-key", id: new Uint8Array([7]) }],
            userVerification: "preferred",
        },
    });
    const options = JSON.parse(sent.options);
    assert.equal(options.rpId, "example.com");
    assert.deepEqual(options.allowCredentials, [{ type: "public-key", id: "Bw" }]);
    assert.ok(credential.response instanceof env.window.AuthenticatorAssertionResponse);
    assert.deepEqual([...new Uint8Array(credential.response.signature)], [3]);
    assert.deepEqual([...new Uint8Array(credential.response.userHandle)], [4]);
    assert.equal(credential.authenticatorAttachment, "platform");
    assert.deepEqual({ ...credential.getClientExtensionResults() }, {});
    const anonymous = page({
        answer: () => ({
            credential: { id: "Bw", rawId: "Bw", type: "public-key", response: { clientDataJSON: "", authenticatorData: "", signature: "" } },
        }),
    });
    const result = await anonymous.window.navigator.credentials.get({ publicKey: { challenge: new Uint8Array([5]) } });
    assert.equal(result.response.userHandle, null);
});

test("non-public-key, conditional, malformed, declined, and unavailable requests use the browser", async () => {
    const env = page();
    const credentials = env.window.navigator.credentials;
    assert.equal(await credentials.get({ password: true }), "native-get");
    assert.equal(await credentials.get({ mediation: "conditional", publicKey: { challenge: new Uint8Array(1) } }), "native-get");
    assert.equal(await credentials.create({ publicKey: { user: null } }), "native-create", "malformed options");
    assert.equal(await credentials.create(creation()), "native-create", "the extension declined");
    const unanswered = page({ answer: () => undefined });
    assert.equal(await unanswered.window.navigator.credentials.create(creation()), "native-create");
    const missing = page({ ready: false, immediateTimers: true });
    assert.equal(await missing.window.navigator.credentials.create(creation()), "native-create", "no extension bridge");
    assert.equal(missing.posted.filter(message => message.data.type === "request").length, 0);
});

test("refusals become DOMExceptions and aborts cancel the extension's prompt", async () => {
    for (const [error, name] of [
        ["InvalidStateError", "InvalidStateError"],
        ["NotAllowedError", "NotAllowedError"],
        ["Something", "NotAllowedError"],
    ]) {
        const env = page({ answer: () => ({ error, message: "No" }) });
        await assert.rejects(env.window.navigator.credentials.create(creation()), { name });
    }
    const silent = page({ answer: () => ({ error: "NotAllowedError" }) });
    await assert.rejects(silent.window.navigator.credentials.get({ publicKey: { challenge: new Uint8Array(1) } }), {
        message: "The request was not allowed.",
    });
    const aborted = page();
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
        aborted.window.navigator.credentials.create({ ...creation(), signal: controller.signal }),
        { name: "AbortError" }
    );
    assert.ok(aborted.posted.some(message => message.data.type === "cancel"));

    // An abort while the prompt is open cancels it; a later result is ignored.
    const waiting = page({ answer: () => undefined });
    waiting.window.postMessage = (data, targetOrigin) => waiting.posted.push({ data, targetOrigin });
    const later = new AbortController();
    const pendingCreate = waiting.window.navigator.credentials.create({ ...creation(), signal: later.signal });
    await new Promise(resolve => setImmediate(resolve));
    later.abort();
    await assert.rejects(pendingCreate, { name: "AbortError" });
    const request = waiting.posted.find(message => message.data.type === "request");
    waiting.deliver({ source: waiting.self, origin: ORIGIN, data: { channel: "pm-passkey", type: "result", id: request.data.id, result: {} } });
    assert.ok(waiting.posted.some(message => message.data.type === "cancel"));
});

test("messages from other windows, origins, or channels are ignored", async () => {
    const env = page({ ready: false, immediateTimers: true });
    for (const event of [
        { source: {}, origin: ORIGIN, data: { channel: "pm-passkey", type: "ready" } },
        { source: env.self, origin: "https://evil.test", data: { channel: "pm-passkey", type: "ready" } },
        { source: env.self, origin: ORIGIN, data: { channel: "other", type: "ready" } },
        { source: env.self, origin: ORIGIN, data: null },
    ])
        env.deliver(event);
    assert.equal(await env.window.navigator.credentials.create(creation()), "native-create");
});

test("pages without WebAuthn are left alone", () => {
    const window = { navigator: {}, location: { origin: ORIGIN } };
    loadScript("webauthn_page.js", vm.createContext(window));
    assert.deepEqual(window.navigator, {});
});
