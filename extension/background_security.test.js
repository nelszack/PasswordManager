const test = require("node:test");
const assert = require("node:assert/strict");
const security = require("./background_security.js");

test("sender domains come from trusted HTTP(S) sender metadata", () => {
    assert.equal(security.senderDomain({ url: "https://Login.Example.COM./path" }), "login.example.com");
    assert.equal(security.senderDomain({ tab: { url: "http://localhost:3000/login" } }), "localhost");
    assert.equal(security.senderDomain({ url: "file:///tmp/login.html" }), null);
    assert.equal(security.senderDomain({ url: "chrome-extension://abcdefghijklmnop/" }), null);
    assert.equal(security.senderDomain({ url: "not a url" }), null);
});

test("sender origins preserve the trusted scheme and port", () => {
    assert.equal(security.senderOrigin({ url: "https://Login.Example.COM./path" }), "https://login.example.com");
    assert.equal(security.senderOrigin({ tab: { url: "http://localhost:3000/login" } }), "http://localhost:3000");
    assert.equal(security.senderOrigin({ url: "file:///tmp/login.html" }), null);
});

test("pending credentials are isolated by browser tab", () => {
    assert.equal(security.pendingStorageKey({ tab: { id: 42 } }), "pmPopupPending:42");
    assert.equal(security.pendingStorageKey({ tab: {} }), null);
    assert.equal(security.pendingStorageKey({}), null);
});

test("TOTP IDs must belong to a matching site credential", () => {
    const accounts = [
        { id: 7, has_totp: true },
        { id: 8, has_totp: false }
    ];
    assert.equal(security.totpEntryAllowed(accounts, 7), true);
    assert.equal(security.totpEntryAllowed(accounts, 8), false);
    assert.equal(security.totpEntryAllowed(accounts, 9), false);
    assert.equal(security.totpEntryAllowed(null, 7), false);
});

test("secure picker messages only come from the extension picker page", () => {
    const picker = "chrome-extension://abcdefghijklmnop/picker.html";
    assert.equal(security.securePickerSender({
        id: "abcdefghijklmnop",
        url: `${picker}?token=secret`
    }, "abcdefghijklmnop", picker), true);
    assert.equal(security.securePickerSender({
        id: "abcdefghijklmnop",
        url: "chrome-extension://abcdefghijklmnop/popup.html"
    }, "abcdefghijklmnop", picker), false);
    assert.equal(security.securePickerSender({
        id: "different",
        url: `${picker}?token=secret`
    }, "abcdefghijklmnop", picker), false);
    assert.equal(security.securePickerSender({
        id: "abcdefghijklmnop",
        url: "https://example.com/picker.html"
    }, "abcdefghijklmnop", picker), false);
});
