const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function loadWorker(context) {
    const execute = name => {
        const filename = path.join(__dirname, name);
        vm.runInContext(fs.readFileSync(filename, "utf8"), context, { filename });
    };
    context.importScripts = (...names) => names.forEach(execute);
    execute("background.js");
}

function securityEnvironment() {
    let listener, nativeListener, disconnect;
    let locked = false;
    let holdLogin = false, heldLoginResponse;
    let holdCredentials = false, heldCredentialResponse;
    let holdSave = false, heldSaveResponse, removedWindowListener;
    let credentialResponse = { success: true, data: JSON.stringify([
        { id: 1, name: "Personal", username: "alice", has_totp: true }
    ]) };
    const requests = [], deliveries = [], removed = [], created = [], badge = [];
    const event = capture => ({ addListener(fn) { capture?.(fn); } });
    const origin = "https://shop.example";
    const chrome = {
        action: { setBadgeText(value) { badge.push(value); }, setBadgeBackgroundColor() {}, setTitle() {} },
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
                        else if (request.action === "getLoginItems") Object.assign(response, credentialResponse);
                        else if (request.action === "getAutofillItems") response.data = JSON.stringify([
                            { id: 2, name: "Visa", kind: "payment-card" }
                        ]);
                        else if (request.action === "getAutofillItem") response.data = JSON.stringify({ id: 2, primary_secret: "synthetic-card" });
                        else response.data = JSON.stringify({ id: 1, password: "synthetic-secret" });
                        if (holdLogin && request.action === "getLoginItem") heldLoginResponse = response;
                        else if (holdCredentials && request.action === "getLoginItems") heldCredentialResponse = response;
                        else if (holdSave && ["saveCredentials", "updateCredentials"].includes(request.action)) heldSaveResponse = response;
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
            onRemoved: event(fn => removedWindowListener = fn)
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
    loadWorker(context);
    const sender = { url: origin, tab: { id: 7, url: origin }, frameId: 0, documentId: "original-document" };
    const pickerSender = { id: chrome.runtime.id, url: chrome.runtime.getURL("picker.html") };
    const message = (request, source = sender) => new Promise(resolve => listener(request, source, resolve));
    return {
        context, requests, deliveries, removed, created, badge, sender, pickerSender, message,
        setCredentialResponse(response) { credentialResponse = response; },
        holdSave() { holdSave = true; },
        releaseSave() { nativeListener(heldSaveResponse); },
        windowRemoved(id) { removedWindowListener(id); },
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

test("vault management cannot be called by websites, content scripts, or other extension pages", async () => {
    const env = securityEnvironment();
    await new Promise(resolve => setImmediate(resolve));
    const manager = { id: "abcdefghijklmnopabcdefghijklmnop", url: "chrome-extension://abcdefghijklmnopabcdefghijklmnop/manager.html" };
    for (const action of ["managerVaults", "managerUnlock", "managerList", "managerItem", "managerCopy", "managerAdd", "managerUpdate", "managerDelete"]) {
        for (const sender of [env.sender, env.pickerSender, { ...manager, id: "different" }, { ...manager, url: manager.url + ".evil" }]) {
            const before = env.requests.length;
            assert.equal((await env.message({ action, entryId: 1, password: "synthetic" }, sender)).success, false);
            assert.equal(env.requests.length, before);
        }
        const before = env.requests.length;
        assert.equal((await env.message({ action, entryId: 1 }, manager)).success, true);
        assert.equal(env.requests.slice(before).filter(request => request.action === action).length, 1);
    }
    assert.equal((await env.message({ action: "managerUnknown" }, manager)).success, false);
});

test("background worker starts, publishes status, and rejects untrusted credential requests", async () => {
    const env = securityEnvironment();
    await new Promise(resolve => setImmediate(resolve));
    assert.ok(env.badge.some(value => value.text === "U"));
    const before = env.requests.length;
    const response = await env.message(
        { action: "getCredentials" },
        { url: "file:///tmp/untrusted.html", tab: { id: 7 } }
    );
    assert.equal(response.success, false);
    assert.equal(response.error, "Invalid page origin");
    assert.equal(env.requests.length, before);
});

test("credential relays enforce tab, frame, token, origin, and single-use writes", async () => {
    for (const action of ["saveRelayedCredentials", "updateRelayedCredentials"]) {
        const env = securityEnvironment();
        await new Promise(resolve => setImmediate(resolve));
        const token = require("node:crypto").randomUUID();
        const child = { ...env.sender, url: "https://embedded.example/login", frameId: 3 };
        const relayRequest = { action: "relayToParent", data: {
            token, domain: "https://embedded.example", username: "alice", password: "synthetic-secret"
        } };
        const forged = await env.message({ ...relayRequest, data: {
            ...relayRequest.data, domain: "https://forged.example"
        } }, child);
        assert.equal(forged.ok, false);
        assert.equal((await env.message(relayRequest, child)).ok, true);
        const lookup = { action: "getRelayedCredentials", token, sourceFrameId: 3, domain: "https://forged.example" };
        const before = env.requests.length;
        for (const [request, sender] of [
            [lookup, child],
            [lookup, { ...env.sender, tab: { id: 8 } }],
            [{ ...lookup, token: require("node:crypto").randomUUID() }, env.sender]
        ]) {
            const rejected = await env.message(request, sender);
            assert.equal(rejected.success, false);
            assert.equal(rejected.error, "Invalid credential relay");
        }
        assert.equal(env.requests.length, before);
        assert.equal((await env.message(lookup)).success, true);
        assert.equal(env.requests.at(-1).domain, "https://embedded.example");

        const write = { ...lookup, action, username: "alice", password: "synthetic-new-secret", id: 1 };
        assert.equal((await env.message(write)).success, true);
        const forwarded = env.requests.find(request => request.action === (
            action === "saveRelayedCredentials" ? "saveCredentials" : "updateCredentials"
        ));
        assert.equal(forwarded.domain, "https://embedded.example");
        if (action === "updateRelayedCredentials") assert.equal(forwarded.entryId, 1);
        const writes = env.requests.filter(request => ["saveCredentials", "updateCredentials"].includes(request.action)).length;
        assert.equal((await env.message(write)).success, false);
        assert.equal(env.requests.filter(request => ["saveCredentials", "updateCredentials"].includes(request.action)).length, writes);

        assert.equal((await env.message(relayRequest, child)).ok, true);
        assert.equal((await env.message({ ...lookup, sourceFrameId: 4 })).success, false);
        assert.equal((await env.message(write)).success, false);
    }
});

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

test("locks and disconnects invalidate pending pickers and save prompts", async t => {
    for (const kind of ["picker", "prompt"]) {
        const operations = kind === "picker"
            ? ["lock-before-poll", "lock-after-poll", "disconnect"]
            : ["lock-after-poll", "disconnect"];
        for (const operation of operations) {
            await t.test(`${kind}: ${operation}`, async () => {
                const env = securityEnvironment();
                const token = kind === "picker" ? await env.open() : (
                    await env.message({ action: "openCredentialPrompt", username: "alice", password: "new-secret" })
                ).token;
                assert.ok(token);
                if (operation === "disconnect") env.disconnect();
                else {
                    env.setLocked();
                    if (operation === "lock-after-poll") await env.message({ action: "getStatus" });
                }
                if (kind === "picker") {
                    const result = await env.message({ action: "completeSecurePicker", token, id: 1 }, env.pickerSender);
                    assert.equal(result.success, false);
                    assert.match(result.error, operation === "lock-before-poll" ? /Vault locked\./ : /expired/);
                    assert.equal(env.deliveries.length, 0);
                } else {
                    assert.equal(env.deliveries.at(-1).message.result.action, "skipped");
                }
                if (operation !== "lock-before-poll") assert.ok(env.removed.includes(42));
            });
        }
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

test("automatic prompts wait for lookup and open only with an available vault", async t => {
    const cases = [
        { name: "successful delayed lookup", hold: true, opens: true },
        { name: "stopped server", response: { success: false, error: "Server is not running" } },
        { name: "disconnected host", response: { success: false, error: "Native messaging host disconnected" } },
        { name: "timed out host", response: { success: false, error: "Native messaging request timed out" } },
        { name: "invalid JSON", response: { success: true, data: "not-json" } },
        { name: "invalid item list", response: { success: true, data: "{}" } },
        { name: "locked vault", locked: true }
    ];
    for (const scenario of cases) {
        await t.test(scenario.name, async () => {
            const env = securityEnvironment();
            await new Promise(resolve => setImmediate(resolve));
            if (scenario.response) env.setCredentialResponse(scenario.response);
            if (scenario.locked) env.setLocked();
            if (scenario.hold) env.holdCredentials();
            const opening = env.message({ action: "openCredentialPrompt", username: "alice", password: "new-secret" });
            assert.equal(env.created.length, 0);
            if (scenario.hold) env.releaseCredentials();
            const result = await opening;
            assert.equal(result.success, true);
            if (scenario.opens) assert.ok(result.token);
            else assert.equal(result.skipped, true);
            assert.equal(env.created.length, scenario.opens ? 1 : 0);
        });
    }
});

test("automatic prompts use summaries and behave identically for every entered password", async () => {
    for (const password of ["existing-secret", "different-secret"]) {
        const env = securityEnvironment();
        const result = await env.message({ action: "openCredentialPrompt", username: "alice", password });
        assert.equal(result.success, true);
        assert.ok(result.token);
        assert.equal(result.matched, undefined);
        assert.equal(env.created.length, 1);
        assert.equal(env.requests.filter(r => r.action !== "status").every(r => r.action === "getLoginItems"), true);
        const sender = { id: env.pickerSender.id, url: env.pickerSender.url.replace("picker.html", "credential_prompt.html") };
        const data = await env.message({ action: "getCredentialPromptData", token: result.token }, sender);
        assert.equal(JSON.stringify(data).includes(password), false);
        assert.deepEqual(JSON.parse(JSON.stringify(data.data.updateTarget)), { id: 1, name: "Personal" });
    }
    for (const response of [{ success: false, error: "Not found." }, { success: true, data: "[]" }]) {
        const env = securityEnvironment(); env.setCredentialResponse(response);
        const result = await env.message({ action: "openCredentialPrompt", username: "alice", password: "new-secret" });
        assert.ok(result.token); assert.equal(env.created.length, 1);
    }
});

test("legacy page lookups deliver only summaries, never unselected passwords", async () => {
    const env = securityEnvironment();
    const result = await env.message({ action: "getCredentials", domain: "https://attacker.example" });
    assert.equal(result.success, true);
    assert.equal(JSON.stringify(result).includes("password"), false);
    const lookup = env.requests.find(r => r.action === "getLoginItems");
    assert.equal(lookup.domain, env.sender.url);
    assert.equal(env.requests.some(r => r.action === "getCredentials" || r.action === "getLoginItem"), false);
});

test("a completing save survives window closure and status invalidation without duplicating the write", async () => {
    const env = securityEnvironment();
    const opened = await env.message({ action: "openCredentialPrompt", username: "alice", password: "new-secret" });
    const sender = { id: env.pickerSender.id, url: env.pickerSender.url.replace("picker.html", "credential_prompt.html") };
    env.holdSave();
    const request = { action: "completeCredentialPrompt", token: opened.token,
        selection: { action: "update", name: "Personal", username: "alice" } };
    const saving = env.message(request, sender);
    const duplicate = await env.message(request, sender);
    assert.equal(duplicate.success, false);
    assert.match(duplicate.error, /already in progress/);
    env.windowRemoved(42);
    env.setLocked();
    await env.message({ action: "getStatus" });
    assert.equal(env.deliveries.some(delivery => delivery.message.result?.action === "skipped"), false);
    env.releaseSave();
    assert.equal((await saving).success, true);
    assert.equal(env.requests.filter(request => request.action === "updateCredentials").length, 1);
    assert.equal(env.deliveries.at(-1).message.result.action, "update");
});
