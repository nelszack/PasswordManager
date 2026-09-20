const test = require("node:test");
const assert = require("node:assert/strict");
const { requestRoute, resultRoute, relayKey, authorizeCredentialRequest } = require("./relay.js");

const token = "01234567-89ab-4cde-8fab-0123456789ab";

test("valid iframe credentials route only to the top frame", () => {
    const data = { token, domain: "https://login.example.com", username: "alice", password: "secret" };
    const route = requestRoute(data, {
        tab: { id: 42 },
        frameId: 7,
        url: "https://login.example.com/session"
    });

    assert.deepEqual(route, {
        tabId: 42,
        frameId: 0,
        message: { action: "relayedLogin", sourceFrameId: 7, data }
    });
});

test("credential relay rejects top frames, mismatched origins, and malformed tokens", () => {
    const data = { token, domain: "https://login.example.com", username: "alice", password: "secret" };
    assert.equal(requestRoute(data, {
        tab: { id: 42 }, frameId: 0, url: "https://login.example.com"
    }), null);
    assert.equal(requestRoute(data, {
        tab: { id: 42 }, frameId: 7, url: "https://attacker.example"
    }), null);
    assert.equal(requestRoute({ ...data, token: "predictable" }, {
        tab: { id: 42 }, frameId: 7, url: "https://login.example.com"
    }), null);
    assert.equal(requestRoute({ ...data, username: null }, {
        tab: { id: 42 }, frameId: 7, url: "https://login.example.com"
    }), null);
    assert.equal(requestRoute(data, {
        tab: { id: 42 }, frameId: 7, url: "file:///tmp/login.html"
    }), null);
    assert.equal(requestRoute(data, {
        tab: {}, frameId: 7, url: "https://login.example.com"
    }), null);
});

test("relayed credential operations require the authorized top frame and token", () => {
    const pending = new Map([[relayKey(42, token), {
        sourceFrameId: 7,
        domain: "https://login.example.com",
        expiresAt: Date.now() + 1000
    }]]);
    const sender = { tab: { id: 42 }, frameId: 0 };
    assert.equal(authorizeCredentialRequest({ token, sourceFrameId: 7 }, sender, pending)?.domain,
        "https://login.example.com");
    assert.equal(authorizeCredentialRequest({ token, sourceFrameId: 8 }, sender, pending), null);
});

test("only the top frame can return a validated result to its source iframe", () => {
    const request = { sourceFrameId: 7, data: { token, action: "update" } };
    const route = resultRoute(request, { tab: { id: 42 }, frameId: 0 });
    assert.deepEqual(route, {
        tabId: 42,
        frameId: 7,
        message: { action: "relayedLoginResult", data: request.data }
    });
    assert.equal(resultRoute(request, { tab: { id: 42 }, frameId: 3 }), null);
    assert.equal(resultRoute({ ...request, data: { token, action: "unknown" } }, {
        tab: { id: 42 }, frameId: 0
    }), null);
});

test("authorization is isolated by tab and can be consumed exactly once", () => {
    const pending = new Map([[relayKey(42, token), {
        sourceFrameId: 7,
        domain: "https://login.example.com",
        expiresAt: Date.now() + 1000
    }]]);
    const request = { token, sourceFrameId: 7 };

    assert.equal(authorizeCredentialRequest(request, {
        tab: { id: 41 }, frameId: 0
    }, pending), null);
    assert.ok(authorizeCredentialRequest(request, {
        tab: { id: 42 }, frameId: 0
    }, pending, true));
    assert.equal(authorizeCredentialRequest(request, {
        tab: { id: 42 }, frameId: 0
    }, pending), null);
});

test("expired relay authorizations are rejected and removed", () => {
    const key = relayKey(42, token);
    const pending = new Map([[key, {
        sourceFrameId: 7,
        domain: "https://login.example.com",
        expiresAt: Date.now()
    }]]);

    assert.equal(authorizeCredentialRequest({ token, sourceFrameId: 7 }, {
        tab: { id: 42 }, frameId: 0
    }, pending), null);
    assert.equal(pending.has(key), false);
});
