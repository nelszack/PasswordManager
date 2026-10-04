const test = require("node:test");
const assert = require("node:assert/strict");
const security = require("./background_security.js");
const manifest = require("./manifest.json");

test("production content scripts are injected only on HTTPS pages", () => {
    assert.deepEqual(manifest.content_scripts[0].matches, ["https://*/*"]);
});

test("sender domains and origins use trusted HTTP(S) metadata without unsafe fallbacks", () => {
    for (const [label, sender, domain, origin] of [
        ["HTTPS sender", { url: "https://Login.Example.COM./path" }, "login.example.com", "https://login.example.com"],
        ["tab fallback", { tab: { url: "http://localhost:3000/login" } }, "localhost", "http://localhost:3000"],
        ["file", { url: "file:///tmp/login.html" }, null, null],
        ["extension", { url: "chrome-extension://abcdefghijklmnop/" }, null, null],
        ["malformed", { url: "not a url" }, null, null],
        ["invalid sender with trusted tab", { url: "not a url", tab: { url: "https://trusted.example/login" } }, null, null]
    ]) {
        assert.equal(security.senderDomain(sender), domain, label);
        assert.equal(security.senderOrigin(sender), origin, label);
    }
});


test("pending credentials are isolated by browser tab", () => {
    assert.equal(security.pendingStorageKey({ tab: { id: 42 } }), "pmPopupPending:42");
    assert.equal(security.pendingStorageKey({ tab: { id: 0 } }), "pmPopupPending:0");
    assert.equal(security.pendingStorageKey({ tab: { id: "42" } }), null);
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
    assert.equal(security.totpEntryAllowed(accounts, 7.5), false);
    assert.equal(security.totpEntryAllowed(accounts, "7"), false);
    assert.equal(security.totpEntryAllowed(accounts, 0), false);
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
    assert.equal(security.securePickerSender({
        id: "abcdefghijklmnop",
        url: "chrome-extension://abcdefghijklmnop/picker.html.evil"
    }, "abcdefghijklmnop", picker), false);
    assert.equal(security.securePickerSender(null, "abcdefghijklmnop", picker), false);

    const credentialPrompt = "chrome-extension://abcdefghijklmnop/credential_prompt.html";
    assert.equal(security.securePickerSender({
        id: "abcdefghijklmnop",
        url: `${credentialPrompt}?token=secret`
    }, "abcdefghijklmnop", credentialPrompt), true);
    assert.equal(security.securePickerSender({
        id: "abcdefghijklmnop",
        url: picker
    }, "abcdefghijklmnop", credentialPrompt), false);
});
