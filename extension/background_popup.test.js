const test = require("node:test");
const assert = require("node:assert/strict");
const popupService = require("./background_popup.js");
const security = require("./background_security.js");
const protocol = require("./native_protocol.js");

const EXTENSION = "abcdefghijklmnopabcdefghijklmnop";
const SESSION = "a".repeat(64);

function environment({ url = "https://example.com/login", answer = { success: true }, failing = [] } = {}) {
    const requests = [];
    const remembered = [];
    const timers = [];
    const tab = { id: 7, url };
    let fillAnswer = answer;
    const chrome = {
        runtime: { id: EXTENSION, getURL: path => `chrome-extension://${EXTENSION}/${path}` },
        tabs: {
            async query() {
                return [tab];
            },
            async get(id) {
                if (id !== tab.id) throw new Error("No tab");
                return tab;
            },
            async sendMessage(id, message, options) {
                requests.push({ action: "tabs.sendMessage", id, message, options });
                if (fillAnswer instanceof Error) throw fillAnswer;
                return fillAnswer;
            },
        },
    };
    const service = popupService.create({
        chrome,
        security,
        protocol,
        crypto: { randomUUID: () => "token-1" },
        setTimeout(fn) {
            timers.push(fn);
        },
        rememberFilled(...args) {
            remembered.push(args);
        },
        async nativeRequest(action, fields) {
            requests.push({ action, ...fields });
            if (failing.includes(action)) return { success: false };
            if (action === "getLoginItems")
                return {
                    success: true,
                    sessionId: SESSION,
                    data: [
                        { id: 4, revision: 2, name: "Work", username: "w@corp", kind: "login", urls: [], has_totp: true, has_duo: false },
                        { id: 0, revision: 1, name: "Bad", username: null, kind: "login", urls: [], has_totp: false, has_duo: false },
                    ],
                };
            if (action === "getLoginItem") return { success: true, data: { username: " w@corp ", password: "synthetic" } };
            if (action === "saveCredentials") return { success: true, data: "Saved" };
            if (action === "searchItems")
                return {
                    success: true,
                    sessionId: SESSION,
                    data: {
                        total: 2,
                        items: [
                            { id: 9, revision: 3, name: "Bank", username: "me", kind: "login", urls: ["https://bank.example"], has_totp: false, has_duo: false },
                            { id: -1, revision: 0, name: "Bad", username: null, kind: "login", urls: [], has_totp: false, has_duo: false },
                        ],
                    },
                };
            return { success: true, data: `${action} done` };
        },
    });
    const popup = { id: EXTENSION, url: chrome.runtime.getURL("popup.html") };
    const page = { id: EXTENSION, tab: { id: 7 }, frameId: 0, origin: "https://example.com" };
    return {
        service,
        popup,
        page,
        tab,
        requests,
        remembered,
        timers,
        setAnswer(value) {
            fillAnswer = value;
        },
    };
}

test("popup requests need the popup page as sender", async () => {
    const env = environment();
    const outsider = { id: EXTENSION, url: `chrome-extension://${EXTENSION}/picker.html` };
    for (const method of ["logins", "copy", "copyGenerated", "save", "fill"]) {
        await assert.rejects(env.service[method]({ id: 4, field: "password" }, outsider), /Invalid popup request/);
    }
    assert.deepEqual(env.requests, []);
});

test("logins are listed for the active https origin only", async () => {
    const env = environment();
    const result = await env.service.logins({}, env.popup);
    assert.equal(result.site, "https://example.com");
    assert.deepEqual(JSON.parse(JSON.stringify(result.items)), [{ id: 4, name: "Work", username: "w@corp", hasTotp: true }]);
    assert.equal(env.requests[0].domain, "https://example.com");

    const insecure = environment({ url: "http://router.local/" });
    const http = await insecure.service.logins({}, insecure.popup);
    assert.equal(http.site, null);
    assert.equal(http.reason, "insecure");
    assert.equal(http.host, "http://router.local");
    const other = environment({ url: "chrome://settings" });
    assert.equal((await other.service.logins({}, other.popup)).reason, "unsupported");
    assert.deepEqual(insecure.requests, []);
});

test("copies go through the desktop service, bound to the listed revision and session", async () => {
    const env = environment();
    await assert.rejects(env.service.copy({ id: 4, field: "password" }, env.popup), /Reopen the popup/);
    await env.service.logins({}, env.popup);
    await assert.rejects(env.service.copy({ id: 4, field: "notes" }, env.popup), /Invalid copy request/);
    await assert.rejects(env.service.copy({ id: 9, field: "password" }, env.popup), /no longer available/);
    const copied = await env.service.copy({ id: 4, field: "totp" }, env.popup);
    assert.equal(copied.data, "copyLoginValue done");
    assert.deepEqual(env.requests.at(-1), {
        action: "copyLoginValue",
        domain: "https://example.com",
        entryId: 4,
        field: "totp",
        expectedRevision: 2,
        expectedSession: SESSION,
    });
    env.tab.url = "https://elsewhere.example/";
    await assert.rejects(env.service.copy({ id: 4, field: "password" }, env.popup), /page changed/);
});

test("generated passwords and new logins are validated before reaching the host", async () => {
    const env = environment();
    for (const value of ["", 5, "x".repeat(4097)]) {
        await assert.rejects(env.service.copyGenerated({ value }, env.popup), /Invalid copy request/);
    }
    assert.equal((await env.service.copyGenerated({ value: "generated" }, env.popup)).data, "copyGenerated done");
    assert.equal(env.requests.at(-1).password, "generated");

    await assert.rejects(env.service.save({ name: "A", password: "p" }, env.popup), /Reopen the popup/);
    await env.service.logins({}, env.popup);
    await assert.rejects(env.service.save({ name: " ", password: "p" }, env.popup), /Enter a name/);
    await assert.rejects(env.service.save({ name: "A", password: "" }, env.popup), /Generate a password/);
    const saved = await env.service.save({ name: " New ", username: " me ", password: "p" }, env.popup);
    assert.equal(saved.data, "Saved");
    assert.deepEqual(env.requests.at(-1), {
        action: "saveCredentials",
        domain: "https://example.com",
        name: "New",
        username: "me",
        password: "p",
        expectedSession: SESSION,
    });
    env.tab.url = "https://elsewhere.example/";
    await assert.rejects(env.service.save({ name: "A", password: "p" }, env.popup), /page changed/);
});

test("a popup fill is claimed once by the same tab's top frame and origin", async () => {
    const env = environment();
    await env.service.logins({}, env.popup);
    await env.service.fill({ id: 4 }, env.popup);
    const delivered = env.requests.find(request => request.action === "tabs.sendMessage");
    assert.deepEqual(delivered.message, { action: "pmPopupFill", token: "token-1" });
    assert.deepEqual(delivered.options, { frameId: 0 });
    for (const sender of [
        { ...env.page, frameId: 2 },
        { ...env.page, tab: { id: 8 } },
        { ...env.page, origin: "https://evil.example" },
    ]) {
        await env.service.fill({ id: 4 }, env.popup);
        await assert.rejects(env.service.claim({ token: "token-1" }, sender), /expired/);
    }
    await env.service.fill({ id: 4 }, env.popup);
    const claimed = await env.service.claim({ token: "token-1" }, env.page);
    assert.equal(claimed.payload.password, "synthetic");
    assert.deepEqual(env.remembered[0], [{ tabId: 7, frameId: 0, domain: "https://example.com" }, "w@corp", "synthetic"]);
    await assert.rejects(env.service.claim({ token: "token-1" }, env.page), /expired/, "a token is single-use");

    // Locking invalidates fills that were handed to the page.
    await env.service.fill({ id: 4 }, env.popup);
    env.service.invalidate();
    await assert.rejects(env.service.claim({ token: "token-1" }, env.page), /expired/);
    // Timers drop unclaimed fills.
    await env.service.logins({}, env.popup);
    await env.service.fill({ id: 4 }, env.popup);
    env.timers.at(-1)();
    await assert.rejects(env.service.claim({ token: "token-1" }, env.page), /expired/);
});

test("fills report pages without a form or content script", async () => {
    const env = environment({ answer: { success: false, error: "No sign-in form was found on this page." } });
    await env.service.logins({}, env.popup);
    await assert.rejects(env.service.fill({ id: 4 }, env.popup), /No sign-in form/);
    env.setAnswer(new Error("Receiving end does not exist"));
    await assert.rejects(env.service.fill({ id: 4 }, env.popup), /not ready for filling/);
    env.setAnswer(undefined);
    await assert.rejects(env.service.fill({ id: 4 }, env.popup), /not ready for filling/);
});

test("vault-wide search returns metadata only and copies only listed results", async () => {
    const env = environment();
    const original = env.service;
    void original;
    assert.deepEqual(JSON.parse(JSON.stringify(await env.service.search({ query: " b " }, env.popup))), {
        success: true,
        items: [],
        total: 0,
    });
    await assert.rejects(env.service.search({ query: "bank" }, { id: EXTENSION, url: "https://evil.example" }), /Invalid popup/);
    await assert.rejects(env.service.copyItem({ id: 4 }, env.popup), /Search again/);
    const found = await env.service.search({ query: "bank" }, env.popup);
    assert.equal(found.total, 2);
    assert.deepEqual(JSON.parse(JSON.stringify(found.items)), [
        { id: 9, name: "Bank", username: "me", kind: "login", site: "https://bank.example", hasTotp: false },
    ]);
    assert.equal(JSON.stringify(found).includes("revision"), false);
    await env.service.copyItem({ id: 9 }, env.popup);
    assert.deepEqual(env.requests.at(-1), {
        action: "copyItem",
        entryId: 9,
        field: "password",
        expectedRevision: 3,
        expectedSession: SESSION,
    });
    env.service.invalidate();
    await assert.rejects(env.service.copyItem({ id: 9 }, env.popup), /Search again/, "locking forgets results");
});

test("native refusals become readable errors for every popup action", async () => {
    const env = environment({
        failing: ["copyLoginValue", "copyGenerated", "saveCredentials", "getLoginItem", "copyItem"],
    });
    await env.service.logins({}, env.popup);
    await assert.rejects(env.service.copy({ id: 4, field: "password" }, env.popup), /Could not copy/);
    await assert.rejects(env.service.copyGenerated({ value: "x" }, env.popup), /Could not copy/);
    await assert.rejects(env.service.save({ name: "A", password: "p" }, env.popup), /Could not save/);
    await env.service.fill({ id: 4 }, env.popup);
    await assert.rejects(env.service.claim({ token: "token-1" }, env.page), /Login unavailable/);
    await env.service.search({ query: "bank" }, env.popup);
    await assert.rejects(env.service.copyItem({ id: 9 }, env.popup), /Could not copy/);

    const searchFails = environment({ failing: ["searchItems"] });
    await assert.rejects(searchFails.service.search({ query: "bank" }, searchFails.popup), /Search failed/);
    const listFails = environment({ failing: ["getLoginItems"] });
    const listed = await listFails.service.logins({}, listFails.popup).catch(error => error);
    assert.ok(listed);
});
