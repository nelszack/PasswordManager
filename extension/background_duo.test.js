const test = require("node:test");
const assert = require("node:assert/strict");
const service = require("./background_duo.js");
const detection = require("./duo_detection.js");

function environment() {
    const sender = { url: "https://login.example/duo", tab: { id: 7 }, frameId: 0, documentId: "doc-one" };
    const popup = { id: "extension", url: "chrome-extension://extension/duo_prompt.html" };
    const created = [], removed = [], calls = [], timers = [];
    let active = true, origin = "https://login.example", locked = false, holdPoll, holdDecision, decisionError;
    let items = [{ id: 1, name: "Work", has_duo: true }];
    let issuerItems = [];
    let pending = [{ id: "request-one", application: "Example VPN", username: "alice", location: "Boise",
        summary: "Login", expires_at: Math.floor(Date.now() / 1000) + 300,
        code_digits: null, unsupported: null, fingerprint: "a".repeat(128) }];
    const chrome = { runtime: { id: "extension", getURL: path => `chrome-extension://extension/${path}` },
        tabs: { get: async () => ({ url: origin }), sendMessage: async (_tab, _message, options) => {
            assert.equal(options.documentId, sender.documentId);
            return { active };
        } }, windows: {
            create: (options, callback) => { created.push(options); callback({ id: 42 }); },
            remove: (id, callback) => { removed.push(id); callback?.(); }
        } };
    const duo = service.create({ chrome, security: require("./background_security.js"), detection,
        protocol: require("./native_protocol.js"), crypto: require("node:crypto").webcrypto,
        setTimeout: (callback, delay) => timers.push({ callback, delay }),
        refreshStatus: async () => ({ native: true, running: true, locked }),
        nativeRequest: async (action, fields) => {
            calls.push({ action, ...fields });
            if (action === "getLoginItems") return { success: true, data: JSON.stringify(items) };
            if (action === "getDuoItems") return { success: true, data: JSON.stringify(issuerItems) };
            if (action === "managerDuoRequests") {
                if (holdPoll) await holdPoll;
                return { success: true, data: pending };
            }
            if (action === "managerDuoRespond") {
                if (holdDecision) await holdDecision;
                if (decisionError) return { success: false, error: decisionError };
                pending = []; return { success: true, data: "Answered" };
            }
            throw new Error("unexpected native action");
        }
    });
    return { duo, sender, popup, calls, created, removed, timers,
        setPending: value => pending = value, setItems: value => items = value,
        setIssuerItems: value => issuerItems = value,
        setActive: value => active = value, setOrigin: value => origin = value, setLocked: value => locked = value,
        setDecisionError: value => decisionError = value,
        holdPoll: () => { let release; holdPoll = new Promise(resolve => release = resolve); return release; },
        holdDecision: () => { let release; holdDecision = new Promise(resolve => release = resolve); return release; },
        token: () => new URL(created.at(-1).url).searchParams.get("token"),
        async open() { await duo.observe({}, sender); return this.token(); },
        decision(r, approve, code = "") { return { token: this.token(), entryId: r.entryId, requestId: r.id,
            fingerprint: r.fingerprint, approve, verificationCode: code }; }
    };
}
const flush = () => new Promise(resolve => setImmediate(resolve));

test("Duo windows require both a site enrollment and a live request; pages get no request data", async () => {
    for (const scenario of ["none", "unrelated", "no request", "locked", "inactive"]) {
        const env = environment();
        if (scenario === "none") env.setItems([]);
        if (scenario === "unrelated") env.setItems([{ id: 2, has_duo: false }]);
        if (scenario === "no request") env.setPending([]);
        if (scenario === "locked") env.setLocked(true);
        if (scenario === "inactive") env.setActive(false);
        await env.duo.observe({}, env.sender).catch(() => {});
        assert.equal(env.created.length, 0, scenario);
        assert.equal(env.calls.some(r => r.action === "managerDuoRespond"), false);
    }
    const env = environment();
    const response = await env.duo.observe({ entryId: 999, domain: "https://evil.example" }, env.sender);
    assert.deepEqual(response, { success: true });
    assert.equal(env.calls[0].domain, "https://login.example");
    assert.equal(env.created.length, 1);
    assert.equal(env.created[0].type, "popup");
    assert.equal(env.calls.some(r => r.action === "managerDuoRespond"), false);
});

test("concurrent detections and dismissing a pending request cannot stack or reopen windows", async () => {
    const env = environment();
    const release = env.holdPoll();
    const opening = [env.duo.observe({}, env.sender), env.duo.observe({}, env.sender)];
    await flush(); release(); await Promise.all(opening);
    assert.equal(env.created.length, 1);
    await env.duo.observe({}, env.sender);
    assert.equal(env.created.length, 1);
    env.duo.windowRemoved(42);
    await env.duo.observe({}, env.sender);
    assert.equal(env.created.length, 1);
    env.setPending([{ id: "new-request", expires_at: Math.floor(Date.now() / 1000) + 300, fingerprint: "b".repeat(128) }]);
    await env.duo.observe({}, env.sender);
    assert.equal(env.created.length, 2);
});

test("only the token-bearing Duo extension window can read or decide requests", async () => {
    const env = environment(), token = await env.open();
    for (const sender of [env.sender, { ...env.popup, id: "other" }, { ...env.popup, url: env.popup.url + ".evil" },
        { ...env.popup, url: env.popup.url.replace("duo_prompt", "manager") }]) {
        await assert.rejects(env.duo.data({ token }, sender), /sender/);
        await assert.rejects(env.duo.complete({ token, cancel: true }, sender), /sender/);
    }
    await assert.rejects(env.duo.data({ token: "forged" }, env.popup), /expired/);
    const data = await env.duo.data({ token }, env.popup);
    const r = data.requests[0];
    await assert.rejects(env.duo.complete({ ...env.decision(r, true), entryId: 999 }, env.popup), /changed/);
    await assert.rejects(env.duo.complete({ ...env.decision(r, true), fingerprint: "old" }, env.popup), /changed/);
    await assert.rejects(env.duo.complete({ ...env.decision(r, true), approve: "yes" }, env.popup), /approve or deny/);
    await env.duo.complete(env.decision(r, true), env.popup);
    const decisions = env.calls.filter(r => r.action === "managerDuoRespond");
    assert.equal(decisions.length, 1); assert.equal(decisions[0].approve, true);
    assert.equal(decisions[0].fingerprint, r.fingerprint);
    await assert.rejects(env.duo.complete(env.decision(r, true), env.popup), /expired/);
});

test("Verified Push needs the typed login-page code; denial and unsupported requests need none", async () => {
    for (const unsupported of [null, "Requires proximity"]) {
        const env = environment();
        env.setPending([{ id: "verified", expires_at: Math.floor(Date.now() / 1000) + 300,
            fingerprint: "c".repeat(128), code_digits: 3, unsupported }]);
        const token = await env.open();
        const r = (await env.duo.data({ token }, env.popup)).requests[0];
        await assert.rejects(env.duo.complete(env.decision(r, true), env.popup), unsupported ? /proximity/ : /verification code/);
        await assert.rejects(env.duo.complete(env.decision(r, true, "12"), env.popup), unsupported ? /proximity/ : /verification code/);
        const approve = !unsupported;
        await env.duo.complete(env.decision(r, approve, "012"), env.popup);
        const decision = env.calls.find(r => r.action === "managerDuoRespond");
        assert.equal(decision.verificationCode, approve ? "012" : "");
        assert.equal(decision.approve, approve);
    }
});

test("navigation, locking and late poll results cannot create or answer a stale window", async () => {
    for (const scenario of ["lock", "navigation", "closed document", "timeout"]) {
        const env = environment();
        const token = await env.open();
        const r = (await env.duo.data({ token }, env.popup)).requests[0];
        if (scenario === "lock") env.duo.invalidate();
        if (scenario === "navigation") env.setOrigin("https://other.example");
        if (scenario === "closed document") env.setActive(false);
        if (scenario === "timeout") env.timers.find(timer => timer.delay === 5 * 60_000).callback();
        await assert.rejects(env.duo.complete(env.decision(r, true), env.popup));
        assert.equal(env.calls.some(call => call.action === "managerDuoRespond"), false);
        assert.ok(env.removed.includes(42));
    }
    const env = environment(), release = env.holdPoll();
    const pending = env.duo.observe({}, env.sender);
    await flush(); env.duo.invalidate(); release();
    await pending.catch(() => {});
    assert.equal(env.created.length, 0);
});

test("duplicate decisions cannot send twice while the first response is pending", async () => {
    const env = environment(), token = await env.open();
    const r = (await env.duo.data({ token }, env.popup)).requests[0];
    const release = env.holdDecision();
    const first = env.duo.complete(env.decision(r, false), env.popup);
    await flush();
    await assert.rejects(env.duo.complete(env.decision(r, false), env.popup), /already in progress/);
    release(); await first;
    assert.equal(env.calls.filter(r => r.action === "managerDuoRespond").length, 1);
});

test("an uncertain decision preserves an error window and blocks retries until a fresh page review", async () => {
    const env = environment(), token = await env.open();
    const r = (await env.duo.data({ token }, env.popup)).requests[0];
    env.setDecisionError("Duo decision timed out");
    await assert.rejects(env.duo.complete(env.decision(r, true), env.popup), /Check the login before retrying/);
    await assert.rejects(env.duo.complete(env.decision(r, true), env.popup), /Check the login before retrying/);
    await assert.rejects(env.duo.data({ token }, env.popup), /Check the login before retrying/);
    await env.duo.observe({}, env.sender);
    assert.equal(env.created.length, 1);
    assert.equal(env.calls.filter(r => r.action === "managerDuoRespond").length, 1);
    assert.equal(env.removed.length, 0);
    await env.duo.complete({ token, cancel: true }, env.popup);
    assert.ok(env.removed.includes(42));
});

test("selected logins follow a same-tab Duo redirect, but never an unrelated host or tab", async () => {
    for (const allowed of [true, false]) {
        const env = environment();
        env.duo.rememberLogin({ sender: env.sender, accounts: [{ id: 1, name: "Work", has_duo: true }] });
        env.setItems([]);
        const url = allowed ? "https://api-test.duosecurity.com" : "https://other.example";
        env.setOrigin(url); env.sender.url = url;
        await env.duo.observe({}, env.sender);
        assert.equal(env.created.length, allowed ? 1 : 0);
        if (allowed) assert.equal((await env.duo.data({ token: env.token() }, env.popup)).sourceOrigin, "https://login.example");
    }
    const env = environment();
    env.duo.rememberLogin({ sender: { ...env.sender, tab: { id: 99 } }, accounts: [{ id: 1, has_duo: true }] });
    env.setItems([]); env.setOrigin("https://api-test.duosecurity.com"); env.sender.url = "https://api-test.duosecurity.com";
    await env.duo.observe({}, env.sender); assert.equal(env.created.length, 0);
});

test("Duo-hosted challenges can find their enrolled issuer without a remembered SSO login", async () => {
    for (const url of ["https://api-test.duosecurity.com", "https://unrelated.example", "http://api-test.duosecurity.com"]) {
        const env = environment();
        env.setItems([{ id: 2, has_duo: false }]);
        env.setIssuerItems([{ id: 1, name: "BYU–Idaho", has_duo: true }]);
        env.setOrigin(url); env.sender.url = url;
        await env.duo.observe({}, env.sender);
        const allowed = url === "https://api-test.duosecurity.com";
        assert.equal(env.created.length, allowed ? 1 : 0, url);
        assert.equal(env.calls.some(call => call.action === "getDuoItems"), allowed, url);
        if (allowed) {
            assert.equal(env.calls.find(call => call.action === "getDuoItems").domain, url);
            assert.equal((await env.duo.data({ token: env.token() }, env.popup)).requests[0].entryId, 1);
        }
        assert.equal(env.calls.some(call => call.action === "managerDuoRespond"), false);
    }
});

test("Duo challenge detection distinguishes sign-in prompts from informational text", () => {
    for (const text of ["Duo Push — Push sent. Check your phone.", "Duo Push: Send me a push", "Duo Push: Verify your identity"]) {
        assert.equal(detection.challenge(text, "https://login.example"), true);
    }
    for (const text of ["Duo Push documentation", "Get started with Duo Push", "Your OTP verification code", "An ordinary login"]) {
        assert.equal(detection.challenge(text, "https://login.example"), false);
    }
    assert.equal(detection.challenge("Check your device", "https://api-test.duosecurity.com"), true);
    // BYU–Idaho's Universal Prompt doesn't use the older "Push sent" wording.
    const universal = 'Check for a Duo Push Verify it\'s you by approving the notification... Sent to "Password Manager" Other options Need help? Secured by Duo';
    for (const url of ["https://secure.byui.edu/cas/login", "https://api-test.duosecurity.com/frame/prompt"]) {
        assert.equal(detection.challenge(universal, url), true, url);
    }
    for (const url of ["http://api-test.duosecurity.com", "https://api-test.duosecurity.com.evil.example", "https://duosecurity.com", "https://api-test.duosecurity.com:8443", "invalid"]) {
        assert.equal(detection.duoOrigin(url), false);
    }
});
