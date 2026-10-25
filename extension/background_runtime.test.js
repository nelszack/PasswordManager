const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { summary, nativeFields, nativeData } = require("./test_fixtures.cjs");

function loadWorker(context) {
    const execute = name => {
        const filename = path.join(__dirname, name);
        vm.runInContext(fs.readFileSync(filename, "utf8"), context, { filename });
    };
    context.importScripts = (...names) => names.forEach(execute);
    execute("background.js");
}

function securityEnvironment({ orphanWindows = [] } = {}) {
    let listener, nativeListener, disconnect;
    let now = Date.now();
    let deliveryError = null;
    let locked = false;
    let holdLogin = false, heldLoginResponse;
    let holdCredentials = false, heldCredentialResponse;
    let holdSave = false, heldSaveResponse, removedWindowListener;
    let credentialResponse = { success: true, data: [
        summary()
    ] };
    const requests = [], deliveries = [], removed = [], removedTabs = [], created = [], badge = [], responses = new Map();
    const sessionData = {};
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
                let portListener;
                return {
                    onMessage: event(fn => { portListener = fn; nativeListener = fn; }),
                    onDisconnect: event(fn => disconnect = fn),
                    postMessage(request) {
                        requests.push(request);
                        const response = { id: request.id, protocolVersion: require("./command_contract.js").protocolVersion, sessionId: "a".repeat(64), success: true, nativeVersion: "0.1.0" };
                        if (request.action === "status") response.data = { locked, version: "0.1.0", warning: null };
                        else if (locked) Object.assign(response, { success: false, error: "Vault locked." });
                        else if (request.action === "getLoginItems") Object.assign(response, credentialResponse);
                        else response.data = nativeData(request.action);
                        if (responses.has(request.action)) Object.assign(response, responses.get(request.action));
                        if (request.operationId && response.success) response.operation = { operationId: request.operationId, state: "committed", revision: null };
                        if (holdLogin && request.action === "getLoginItem") heldLoginResponse = response;
                        else if (holdCredentials && request.action === "getLoginItems") heldCredentialResponse = response;
                        else if (holdSave && ["saveCredentials", "updateCredentials"].includes(request.action)) heldSaveResponse = response;
                        else queueMicrotask(() => portListener(response));
                    }
                };
            }
        },
        storage: { local: { set() {} }, session: {
            get(key, callback) { callback(key === null ? { ...sessionData } : { [key]: sessionData[key] }); },
            set(value, callback) { Object.assign(sessionData, value); callback(); },
            remove(key, callback) { delete sessionData[key]; callback(); }
        } },
        tabs: {
            get: async () => ({ url: origin }),
            remove(id, callback) { removedTabs.push(id); callback?.(); },
            sendMessage: async (tab, message, options) => {
                if (deliveryError) throw new Error(deliveryError);
                deliveries.push({ tab, message, options });
            }
        },
        windows: {
            getAll(_options, callback) { callback(orphanWindows); },
            create(options, callback) { created.push(options); callback({ id: 42 }); },
            remove(id, callback) { removed.push(id); callback?.(); },
            onRemoved: event(fn => removedWindowListener = fn)
        }
    };
    const context = vm.createContext({
        chrome, URL, TextEncoder, crypto: require("node:crypto").webcrypto,
        Date: class extends Date { static now() { return now; } },
        setTimeout() { return 1; }, clearTimeout() {}, setInterval() {}, clearInterval() {}, queueMicrotask
    });
    loadWorker(context);
    const sender = { url: origin, tab: { id: 7, url: origin }, frameId: 0, documentId: "original-document" };
    const pickerSender = { id: chrome.runtime.id, url: chrome.runtime.getURL("picker.html") };
    const message = (request, source = sender) => new Promise(resolve => listener(request, source, resolve));
    return {
        context, requests, deliveries, removed, removedTabs, created, badge, sender, pickerSender, message,
        advanceTime(milliseconds) { now += milliseconds; },
        failDelivery(error) { deliveryError = error; },
        setCredentialResponse(response) { credentialResponse = response; },
        setNativeResponse(action, response) { responses.set(action, response); },
        holdSave() { holdSave = true; },
        releaseSave() { nativeListener(heldSaveResponse); },
        windowRemoved(id) { removedWindowListener(id); },
        holdCredentials() { holdCredentials = true; },
        releaseCredentials() { nativeListener(heldCredentialResponse); },
        setLocked(value = true) { locked = value; },
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
    for (const action of ["managerVaults", "managerUnlock", "managerList", "managerItem", "managerCopy", "managerAdd", "managerUpdate", "managerDelete", "managerDuoRequests", "managerDuoRespond"]) {
        for (const sender of [env.sender, env.pickerSender, { ...manager, id: "different" }, { ...manager, url: manager.url + ".evil" }]) {
            const before = env.requests.length;
            assert.equal((await env.message({ action, entryId: 1, password: "synthetic" }, sender)).success, false);
            assert.equal(env.requests.length, before);
        }
        const before = env.requests.length;
        assert.equal((await env.message({ action, ...nativeFields(action) }, manager)).success, true);
        assert.equal(env.requests.slice(before).filter(request => request.action === action).length, 1);
    }
    assert.equal((await env.message({ action: "managerUnknown" }, manager)).success, false);
});

test("background worker publishes status and rejects obsolete credential commands", async () => {
    const env = securityEnvironment();
    await new Promise(resolve => setImmediate(resolve));
    assert.ok(env.badge.some(value => value.text === "U"));
    const before = env.requests.length;
    for (const action of ["getCredentials", "saveCredentials", "updateCredentials", "getRelayedCredentials", "saveRelayedCredentials", "updateRelayedCredentials", "relayToParent", "relayLoginResult"]) {
        const response = await env.message({ action, username: "alice", id: 1 });
        assert.equal(response.success, false, action);
        assert.equal(response.error, "Unsupported extension request", action);
    }
    assert.equal(env.requests.length, before);
});

test("pending navigation records use trusted origins and can be consumed only once through the router", async () => {
    const env = securityEnvironment();
    const stored = await env.message({ action: "setPendingCredentials", pending: { username: "alice" } });
    assert.equal(stored.success, true);
    const consumed = await env.message({ action: "consumePendingCredentials" });
    assert.equal(consumed.pending.domain, "https://shop.example");
    assert.equal((await env.message({ action: "consumePendingCredentials" })).pending, null);
    await env.message({ action: "setPendingCredentials", pending: { username: "alice" } });
    assert.equal((await env.message({ action: "clearPendingCredentials" })).success, true);
    assert.equal((await env.message({ action: "consumePendingCredentials" })).pending, null);
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

test("unchanged selected logins skip prompts across same-origin login steps", async () => {
    const env = securityEnvironment();
    const token = await env.open();
    assert.equal((await env.message({ action: "completeSecurePicker", token, id: 1 }, env.pickerSender)).success, true);
    const windows = env.created.length;
    for (const [username, sender] of [
        ["alice", env.sender],
        ["", { ...env.sender, url: "https://shop.example/password", documentId: "next-document" }],
        ["alice", { ...env.sender, url: "https://shop.example/signed-in", documentId: "redirected-document" }]
    ]) {
        const result = await env.message({ action: "openCredentialPrompt", username, password: "synthetic-secret" }, sender);
        assert.equal(result.success, true);
        assert.equal(result.skipped, true);
        assert.equal(result.token, undefined);
    }
    assert.equal(env.created.length, windows);
    assert.equal(env.requests.filter(request => request.action === "getLoginItem").length, 1);
    assert.equal(env.requests.some(request => ["saveCredentials", "updateCredentials"].includes(request.action)), false);
});

test("changed credentials and other tabs, frames, or origins still open prompts", async t => {
    for (const scenario of [
        { name: "changed password", password: "changed-secret" },
        { name: "changed username", username: "bob" },
        { name: "other tab", sender: { tab: { id: 8 } } },
        { name: "other frame", sender: { frameId: 3 } },
        { name: "other hostname", sender: { url: "https://other.example" } },
        { name: "other scheme", sender: { url: "http://shop.example" } },
        { name: "other port", sender: { url: "https://shop.example:8443" } },
        { name: "expired selection", advance: 10 * 60_000 }
    ]) {
        await t.test(scenario.name, async () => {
            const env = securityEnvironment();
            const token = await env.open();
            await env.message({ action: "completeSecurePicker", token, id: 1 }, env.pickerSender);
            if (scenario.advance) env.advanceTime(scenario.advance);
            const result = await env.message({ action: "openCredentialPrompt",
                username: scenario.username || "alice", password: scenario.password || "synthetic-secret"
            }, { ...env.sender, ...scenario.sender });
            assert.ok(result.token);
            assert.equal(result.skipped, undefined);
        });
    }
});

test("failed delivery and vault invalidation discard selected-login fingerprints", async t => {
    for (const action of ["failed delivery", "lock", "disconnect"]) {
        await t.test(action, async () => {
            const env = securityEnvironment();
            const token = await env.open();
            if (action === "failed delivery") env.failDelivery("Document disappeared");
            const selection = await env.message({ action: "completeSecurePicker", token, id: 1 }, env.pickerSender);
            assert.equal(selection.success, action !== "failed delivery");
            if (action === "lock") { env.setLocked(); await env.message({ action: "getStatus" }); }
            if (action === "disconnect") env.disconnect();
            env.failDelivery(null);
            env.setLocked(false);
            const result = await env.message({ action: "openCredentialPrompt", username: "alice", password: "synthetic-secret" });
            assert.ok(result.token);
        });
    }
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
                    assert.equal(env.deliveries.filter(delivery => delivery.message.payload !== null).length, 0);
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
    await new Promise(resolve => setImmediate(resolve));
    const duplicate = await env.message({ action: "completeSecurePicker", token, id: 1 }, env.pickerSender);
    assert.equal(duplicate.success, false);
    assert.match(duplicate.error, /already in progress/);
    env.setLocked();
    await env.message({ action: "getStatus" });
    env.releaseLogin();
    const result = await selection;
    assert.equal(result.success, false);
    assert.match(result.error, /expired/);
    assert.equal(env.deliveries.length, 1);
    assert.equal(env.deliveries[0].message.payload, null);
});

test("automatic prompts wait for lookup and open only with an available vault", async t => {
    const cases = [
        { name: "successful delayed lookup", hold: true, opens: true },
        { name: "stopped server", response: { success: false, error: "Server is not running" } },
        { name: "invalid JSON", response: { success: true, data: "not-json" } },
        { name: "invalid item list", response: { success: true, data: {} } },
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
            if (scenario.hold) { await new Promise(resolve => setImmediate(resolve)); env.releaseCredentials(); }
            const result = await opening;
            assert.equal(result.success, true);
            if (scenario.opens) assert.ok(result.token);
            else assert.equal(result.skipped, true);
            assert.equal(env.created.length, scenario.opens ? 1 : 0);
        });
    }
});

test("automatic prompts use summaries and never compare unselected vault passwords", async () => {
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
        assert.deepEqual(JSON.parse(JSON.stringify(data.data.updateTarget)), { id: 1, revision: 1, name: "Personal" });
    }
    for (const response of [{ success: false, error: "Not found." }, { success: true, data: [] }]) {
        const env = securityEnvironment(); env.setCredentialResponse(response);
        const result = await env.message({ action: "openCredentialPrompt", username: "alice", password: "new-secret" });
        assert.ok(result.token); assert.equal(env.created.length, 1);
    }
});


test("a completing save survives window closure and status invalidation without duplicating the write", async () => {
    const env = securityEnvironment();
    const opened = await env.message({ action: "openCredentialPrompt", username: "alice", password: "new-secret" });
    const sender = { id: env.pickerSender.id, url: env.pickerSender.url.replace("picker.html", "credential_prompt.html") };
    env.holdSave();
    const request = { action: "completeCredentialPrompt", token: opened.token,
        selection: { action: "update", name: "Personal", username: "alice" } };
    const saving = env.message(request, sender);
    await new Promise(resolve => setImmediate(resolve));
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

test("a fresh worker closes orphan decision windows and rejects their tokens before accepting new work", async () => {
    const prefix = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
    const env = securityEnvironment({ orphanWindows: [
        { id: 91, tabs: [{ id: 101, url: `${prefix}picker.html?token=old-picker` }] },
        { id: 92, tabs: [{ id: 102, url: `${prefix}credential_prompt.html?token=old-save` }] },
        { id: 93, tabs: [{ id: 103, url: `${prefix}duo_prompt.html?token=old-duo` }] },
        { id: 96, tabs: [{ id: 104, url: `${prefix}picker.html#restored` }, { id: 105, url: "https://example.com" }] },
        { id: 94, tabs: [{ url: `${prefix}manager.html` }] },
        { id: 95, tabs: [{ url: "https://example.com/picker.html" }] }
    ] });
    const response = await env.message({ action: "getSecurePickerData", token: "old-picker" }, env.pickerSender);
    assert.equal(response.success, false);
    assert.deepEqual(env.removedTabs, [101, 102, 103, 104]);
    assert.deepEqual(env.removed, []);
    const token = await env.open();
    assert.equal((await env.message({ action: "getSecurePickerData", token }, env.pickerSender)).success, true);
});

test("only the manager may acknowledge unknown outcomes and content scripts cannot request a native lock", async () => {
    const env = securityEnvironment();
    const before = env.requests.length;
    for (const sender of [env.sender, env.pickerSender]) {
        assert.equal((await env.message({ action: "acknowledgeUnknownOperation", operationId: "unknown-save", inspected: true }, sender)).success, false);
        assert.equal((await env.message({ action: "lockVault" }, sender)).success, false);
    }
    assert.equal(env.requests.length, before);
    const manager = { id: env.pickerSender.id, url: env.pickerSender.url.replace("picker.html", "manager.html") };
    assert.equal((await env.message({ action: "acknowledgeUnknownOperation", operationId: "unchecked", inspected: true }, manager)).success, false);
});
