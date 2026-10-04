const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

test("background worker starts, publishes status, and rejects untrusted credential requests", async () => {
    let messageListener;
    let nativeMessageListener;
    const badge = [];
    const event = callback => ({ addListener(listener) { callback?.(listener); } });
    const chrome = {
        action: {
            setBadgeText(value) { badge.push(value); },
            setBadgeBackgroundColor() {},
            setTitle() {}
        },
        alarms: { create() {}, onAlarm: event() },
        runtime: {
            id: "abcdefghijklmnopabcdefghijklmnop",
            lastError: null,
            getManifest: () => ({ version: "1.6", version_name: "0.1.0" }),
            getURL: value => `chrome-extension://abcdefghijklmnopabcdefghijklmnop/${value}`,
            onInstalled: event(),
            onStartup: event(),
            onMessage: event(listener => { messageListener = listener; }),
            sendMessage(_message, callback) { callback?.(); },
            connectNative() {
                return {
                    onMessage: event(listener => { nativeMessageListener = listener; }),
                    onDisconnect: event(),
                    postMessage(request) {
                        queueMicrotask(() => nativeMessageListener({
                            id: request.id, success: true, nativeVersion: "0.1.0",
                            data: "Status: unlocked\nVersion: 0.1.0"
                        }));
                    }
                };
            }
        },
        storage: {
            local: { set() {} },
            session: {
                get(_key, callback) { callback({}); },
                set(_value, callback) { callback?.(); },
                remove(_key, callback) { callback?.(); }
            }
        },
        tabs: { sendMessage() { return Promise.resolve(); } },
        windows: {
            create() { return Promise.resolve({ id: 1 }); },
            remove() { return Promise.resolve(); },
            onRemoved: event()
        }
    };
    const context = {
        chrome,
        PasswordManagerRelay: require("./relay.js"),
        PasswordManagerSecurity: require("./background_security.js"),
        PasswordManagerCredentialPrompt: require("./credential_prompt_state.js"),
        PasswordManagerBackgroundState: require("./background_state.js"),
        PasswordManagerNativeProtocol: require("./native_protocol.js"),
        PasswordManagerPendingCredentials: require("./pending_credentials.js"),
        importScripts() {},
        URL, Map, Set, Date, JSON, Promise, Error,
        setTimeout, clearTimeout, queueMicrotask,
        setInterval() { return 1; }
    };
    const filename = path.resolve(__dirname, "background.js");
    vm.runInNewContext(fs.readFileSync(filename, "utf8"), context, { filename });
    await new Promise(resolve => setImmediate(resolve));

    assert.equal(typeof messageListener, "function");
    assert.ok(badge.some(value => value.text === "U"));

    let response;
    assert.equal(messageListener(
        { action: "getCredentials" },
        { url: "file:///tmp/untrusted.html", tab: { id: 7 } },
        value => { response = value; }
    ), true);
    assert.equal(response.success, false);
    assert.equal(response.error, "Invalid page origin");
});

function securityEnvironment() {
    let listener, nativeListener, disconnect;
    let locked = false;
    let holdLogin = false, heldLoginResponse;
    let holdCredentials = false, heldCredentialResponse;
    let credentialResponse = { success: true, data: "[]" };
    const requests = [], deliveries = [], removed = [], created = [];
    const event = capture => ({ addListener(fn) { capture?.(fn); } });
    const origin = "https://shop.example";
    const chrome = {
        action: { setBadgeText() {}, setBadgeBackgroundColor() {}, setTitle() {} },
        alarms: { create() {}, onAlarm: event() },
        runtime: {
            id: "abcdefghijklmnopabcdefghijklmnop", lastError: null,
            getManifest: () => ({ version: "1.6", version_name: "0.1.0" }),
            getURL: value => `chrome-extension://abcdefghijklmnopabcdefghijklmnop/${value}`,
            onInstalled: event(), onStartup: event(), onMessage: event(fn => listener = fn),
            sendMessage(_message, callback) { callback?.(); },
            connectNative() {
                return {
                    onMessage: event(fn => nativeListener = fn),
                    onDisconnect: event(fn => disconnect = fn),
                    postMessage(request) {
                        requests.push(request);
                        const response = { id: request.id, success: true, nativeVersion: "0.1.0" };
                        if (request.action === "status") response.data = `Status: ${locked ? "Locked" : "Unlocked"}\nVersion: 0.1.0`;
                        else if (locked) Object.assign(response, { success: false, error: "Vault locked." });
                        else if (request.action === "getCredentials") Object.assign(response, credentialResponse);
                        else if (request.action === "getLoginItems") response.data = JSON.stringify([
                            { id: 1, name: "Personal", username: "alice", has_totp: true }
                        ]);
                        else if (request.action === "getAutofillItems") response.data = JSON.stringify([
                            { id: 2, name: "Visa", kind: "payment-card" }
                        ]);
                        else if (request.action === "getAutofillItem") response.data = JSON.stringify({ id: 2, primary_secret: "synthetic-card" });
                        else response.data = JSON.stringify({ id: 1, password: "synthetic-secret" });
                        if (holdLogin && request.action === "getLoginItem") heldLoginResponse = response;
                        else if (holdCredentials && request.action === "getCredentials") heldCredentialResponse = response;
                        else queueMicrotask(() => nativeListener(response));
                    }
                };
            }
        },
        storage: { local: { set() {} } },
        tabs: {
            get: async () => ({ url: origin }),
            sendMessage: async (tab, message, options) => { deliveries.push({ tab, message, options }); }
        },
        windows: {
            create(options, callback) { created.push(options); callback({ id: 42 }); },
            remove(id, callback) { removed.push(id); callback?.(); },
            onRemoved: event()
        }
    };
    const context = vm.createContext({
        chrome, importScripts() {}, URL, crypto: require("node:crypto").webcrypto,
        setTimeout() { return 1; }, clearTimeout() {}, setInterval() {}, queueMicrotask,
        PasswordManagerRelay: require("./relay.js"),
        PasswordManagerSecurity: require("./background_security.js"),
        PasswordManagerCredentialPrompt: require("./credential_prompt_state.js"),
        PasswordManagerBackgroundState: require("./background_state.js"),
        PasswordManagerNativeProtocol: require("./native_protocol.js"),
        PasswordManagerPendingCredentials: require("./pending_credentials.js")
    });
    vm.runInContext(fs.readFileSync(path.join(__dirname, "background.js"), "utf8"), context);
    const sender = { url: origin, tab: { id: 7, url: origin }, frameId: 0, documentId: "original-document" };
    const pickerSender = { id: chrome.runtime.id, url: chrome.runtime.getURL("picker.html") };
    const message = (request, source = sender) => new Promise(resolve => listener(request, source, resolve));
    return {
        context, requests, deliveries, removed, created, sender, pickerSender, message,
        setCredentialResponse(response) { credentialResponse = response; },
        holdCredentials() { holdCredentials = true; },
        releaseCredentials() { nativeListener(heldCredentialResponse); },
        setLocked() { locked = true; },
        holdLogin() { holdLogin = true; },
        releaseLogin() { nativeListener(heldLoginResponse); },
        disconnect() { disconnect(); },
        async open(source = sender, kind = "login") {
            await new Promise(resolve => setImmediate(resolve));
            const response = await message({ action: "openSecurePicker", kind }, source);
            assert.equal(response.success, true, response.error);
            await new Promise(resolve => setImmediate(resolve));
            return response.token;
        }
    };
}

test("picker fetches only the selected login and targets the originating document", async () => {
    const env = securityEnvironment();
    const token = await env.open();
    const data = await env.message({ action: "getSecurePickerData", token }, env.pickerSender);
    assert.equal(data.origin, "https://shop.example");
    assert.equal(data.crossOrigin, false);
    assert.equal(JSON.stringify(data).includes("password"), false);
    assert.equal(env.requests.some(request => request.action === "getLoginItem"), false);
    const result = await env.message({ action: "completeSecurePicker", token, id: 1 }, env.pickerSender);
    assert.equal(result.success, true, result.error);
    assert.equal(env.deliveries[0].message.payload.password, "synthetic-secret");
    assert.equal(env.deliveries[0].options.documentId, "original-document");
    assert.equal(env.requests.find(request => request.action === "getLoginItem").domain, env.sender.url);
});

test("a server lock before the next status poll prevents login delivery", async () => {
    const env = securityEnvironment();
    const token = await env.open();
    env.setLocked();
    const result = await env.message({ action: "completeSecurePicker", token, id: 1 }, env.pickerSender);
    assert.equal(result.success, false);
    assert.equal(result.error, "Vault locked.");
    assert.equal(env.deliveries.length, 0);
});

test("locked status and native disconnect invalidate already open pickers", async () => {
    for (const operation of ["lock", "disconnect"]) {
        const env = securityEnvironment();
        const token = await env.open();
        if (operation === "lock") {
            env.setLocked();
            await env.message({ action: "getStatus" });
        } else env.disconnect();
        const result = await env.message({ action: "completeSecurePicker", token, id: 1 }, env.pickerSender);
        assert.equal(result.success, false);
        assert.match(result.error, /expired/);
        assert.equal(env.deliveries.length, 0);
        assert.ok(env.removed.includes(42));
    }
});

test("embedded card autofill requires confirmation of the browser-derived origins", async () => {
    const env = securityEnvironment();
    const sender = { ...env.sender, url: "https://embedded.example/form", frameId: 3 };
    const token = await env.open(sender, "payment-card");
    const data = await env.message({ action: "getSecurePickerData", token }, env.pickerSender);
    assert.equal(data.origin, "https://embedded.example");
    assert.equal(data.topOrigin, "https://shop.example");
    assert.equal(data.crossOrigin, true);
    const rejected = await env.message({ action: "completeSecurePicker", token, id: 2 }, env.pickerSender);
    assert.equal(rejected.success, false);
    assert.equal(env.requests.some(request => request.action === "getAutofillItem"), false);
    const accepted = await env.message({ action: "completeSecurePicker", token, id: 2, confirmCrossOrigin: true }, env.pickerSender);
    assert.equal(accepted.success, true, accepted.error);
    assert.equal(env.deliveries[0].message.payload.primary_secret, "synthetic-card");
});

test("locking cancels an in-flight selection and duplicate clicks cannot deliver twice", async () => {
    const env = securityEnvironment();
    const token = await env.open();
    env.holdLogin();
    const selection = env.message({ action: "completeSecurePicker", token, id: 1 }, env.pickerSender);
    const duplicate = await env.message({ action: "completeSecurePicker", token, id: 1 }, env.pickerSender);
    assert.equal(duplicate.success, false);
    assert.match(duplicate.error, /already in progress/);
    env.setLocked();
    await env.message({ action: "getStatus" });
    env.releaseLogin();
    const result = await selection;
    assert.equal(result.success, false);
    assert.match(result.error, /expired/);
    assert.equal(env.deliveries.length, 0);
});

test("automatic save prompts wait for a successful lookup before opening any window", async () => {
    const env = securityEnvironment();
    await new Promise(resolve => setImmediate(resolve));
    env.holdCredentials();
    const opening = env.message({ action: "openCredentialPrompt", username: "alice", password: "new-secret" });
    assert.equal(env.created.length, 0);
    env.releaseCredentials();
    const result = await opening;
    assert.equal(result.success, true);
    assert.ok(result.token);
    assert.equal(env.created.length, 1);
});

test("stopped, locked, disconnected, and malformed backends never open automatic prompts", async () => {
    for (const response of [
        { success: false, error: "Server is not running" },
        { success: false, error: "Native messaging host disconnected" },
        { success: false, error: "Native messaging request timed out" },
        { success: true, data: "not-json" },
        { success: true, data: "{}" }
    ]) {
        const env = securityEnvironment();
        env.setCredentialResponse(response);
        const result = await env.message({ action: "openCredentialPrompt", username: "alice", password: "new-secret" });
        assert.equal(result.success, true);
        assert.equal(result.skipped, true);
        assert.equal(env.created.length, 0);
    }
    const env = securityEnvironment();
    env.setLocked();
    const result = await env.message({ action: "openCredentialPrompt", username: "alice", password: "new-secret" });
    assert.equal(result.skipped, true);
    assert.equal(env.created.length, 0);
});

test("new sites still prompt while exact matches do not flash a popup", async () => {
    for (const response of [
        { success: false, error: "Not found." },
        { success: true, data: "[]" },
        { success: true, data: JSON.stringify([{ id: 1, username: "alice", password: "existing-secret" }]) }
    ]) {
        const env = securityEnvironment();
        env.setCredentialResponse(response);
        const result = await env.message({ action: "openCredentialPrompt", username: "alice", password: "existing-secret" });
        if (response.data?.includes("existing-secret")) {
            assert.equal(result.matched, true);
            assert.equal(env.created.length, 0);
        } else {
            assert.ok(result.token);
            assert.equal(env.created.length, 1);
        }
    }
});

test("disconnecting or locking closes an existing automatic save prompt", async () => {
    for (const operation of ["lock", "disconnect"]) {
        const env = securityEnvironment();
        await new Promise(resolve => setImmediate(resolve));
        const opened = await env.message({ action: "openCredentialPrompt", username: "alice", password: "new-secret" });
        assert.ok(opened.token);
        if (operation === "lock") {
            env.setLocked();
            await env.message({ action: "getStatus" });
        } else env.disconnect();
        assert.ok(env.removed.includes(42));
        assert.equal(env.deliveries.at(-1).message.result.action, "skipped");
    }
});
