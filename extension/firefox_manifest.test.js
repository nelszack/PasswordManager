const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { firefoxManifest, FIREFOX_EXTENSION_ID } = require("../scripts/firefox_manifest.cjs");

const read = name => fs.readFileSync(path.join(__dirname, name), "utf8");

test("the Firefox manifest loads the bundled worker as an event page with a fixed add-on ID", () => {
    const chrome = JSON.parse(read("manifest.json"));
    const firefox = firefoxManifest(chrome);
    assert.equal(firefox.background.service_worker, undefined);
    assert.deepEqual(firefox.background.scripts, ["background_runtime.js"]);
    assert.equal(firefox.browser_specific_settings.gecko.id, FIREFOX_EXTENSION_ID);
    assert.equal(firefox.browser_specific_settings.gecko.strict_min_version, "128.0");
    assert.equal(firefox.minimum_chrome_version, undefined);
    assert.deepEqual(firefox.permissions, chrome.permissions);
    assert.deepEqual(firefox.commands, chrome.commands);
    assert.ok(chrome.background.service_worker, "the Chrome manifest is not modified");
    assert.throws(() => firefoxManifest({ background: {} }), /service worker/);
});

test("the pinned Chrome key yields the native host's default extension ID", () => {
    const chrome = JSON.parse(read("manifest.json"));
    const digest = require("node:crypto")
        .createHash("sha256")
        .update(Buffer.from(chrome.key, "base64"))
        .digest("hex")
        .slice(0, 32);
    const id = [...digest].map(c => String.fromCharCode(97 + parseInt(c, 16))).join("");
    const rust = fs.readFileSync(path.join(__dirname, "../src/native_messaging.rs"), "utf8");
    assert.ok(rust.includes(`CHROME_EXTENSION_ID: &str = "${id}"`), id);
    assert.equal(firefoxManifest(chrome).key, undefined, "Firefox ignores Chrome keys");
});

test("the Firefox add-on ID matches the native host's default", () => {
    const rust = fs.readFileSync(path.join(__dirname, "../src/native_messaging.rs"), "utf8");
    assert.ok(rust.includes(`FIREFOX_EXTENSION_ID: &str = "${FIREFOX_EXTENSION_ID}"`));
});
