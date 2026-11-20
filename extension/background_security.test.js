const test = require("node:test");
const assert = require("node:assert/strict");
const security = require("./background_security.js");
const manifest = require("./manifest.json");

test("production content scripts are injected only on HTTPS pages", () => {
    assert.deepEqual(manifest.content_scripts[0].matches, ["https://*/*"]);
});

test("sender origins use the browser-computed HTTP(S) origin without unsafe fallbacks", () => {
    for (const [label, sender, origin] of [
        ["HTTPS sender", { origin: "https://Login.Example.COM.", url: "https://login.example.com/path" }, "https://login.example.com"],
        ["HTTP port", { origin: "http://localhost:3000", url: "http://localhost:3000/login" }, "http://localhost:3000"],
        // A CSP-sandboxed document keeps its site's URL but has an opaque origin.
        ["opaque sandboxed document", { origin: "null", url: "https://victim.example/login" }, null],
        ["opaque sandbox in a trusted tab", { origin: "null", url: "https://victim.example/", tab: { url: "https://victim.example/" } }, null],
        // A frame never inherits the top-level page's origin.
        ["URL without origin", { url: "https://victim.example/login" }, null],
        ["tab without origin", { tab: { url: "https://victim.example/login" } }, null],
        ["file", { origin: "file://", url: "file:///tmp/login.html" }, null],
        ["extension", { origin: "chrome-extension://abcdefghijklmnop", url: "chrome-extension://abcdefghijklmnop/" }, null],
        ["malformed", { origin: "not a url" }, null],
        ["non-string", { origin: { toString: () => "https://victim.example" } }, null],
        ["missing sender", null, null],
    ]) {
        assert.equal(security.senderOrigin(sender), origin, label);
    }
    assert.equal(security.urlOrigin("https://Shop.Example./cart?x=1"), "https://shop.example");
    assert.equal(security.urlOrigin("chrome://settings"), null);
    assert.equal(security.urlOrigin(undefined), null);
});

test("pending credentials are isolated by browser tab", () => {
    assert.equal(security.pendingStorageKey({ tab: { id: 42 } }), "pmPopupPending:42");
    assert.equal(security.pendingStorageKey({ tab: { id: 0 } }), "pmPopupPending:0");
    assert.equal(security.pendingStorageKey({ tab: { id: "42" } }), null);
    assert.equal(security.pendingStorageKey({ tab: {} }), null);
    assert.equal(security.pendingStorageKey({}), null);
});

test("secure picker messages only come from the extension picker page", () => {
    const picker = "chrome-extension://abcdefghijklmnop/picker.html";
    const credentialPrompt = "chrome-extension://abcdefghijklmnop/credential_prompt.html";
    const sender = { id: "abcdefghijklmnop", url: `${picker}?token=secret` };
    for (const [label, source, page, allowed] of [
        ["picker query token", sender, picker, true],
        ["wrong extension page", { ...sender, url: "chrome-extension://abcdefghijklmnop/popup.html" }, picker, false],
        ["wrong extension ID", { ...sender, id: "different" }, picker, false],
        ["website origin", { ...sender, url: "https://example.com/picker.html" }, picker, false],
        ["different opaque extension origin", { ...sender, url: "chrome-extension://other/picker.html" }, picker, false],
        ["opaque file origin", { ...sender, url: "file:///picker.html" }, picker, false],
        ["opaque custom scheme", { ...sender, url: "custom://abcdefghijklmnop/picker.html" }, picker, false],
        ["path suffix", { ...sender, url: `${picker}.evil` }, picker, false],
        ["missing sender", null, picker, false],
        ["prompt query token", { ...sender, url: `${credentialPrompt}?token=secret` }, credentialPrompt, true],
        ["picker cannot impersonate prompt", { ...sender, url: picker }, credentialPrompt, false]
    ]) {
        assert.equal(security.securePickerSender(source, sender.id, page), allowed, label);
    }
});
