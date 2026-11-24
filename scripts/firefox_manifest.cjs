// Derives the Firefox manifest from the Chrome manifest. Firefox MV3 runs
// background scripts as an event page rather than a service worker, needs a
// fixed add-on ID for native messaging, and requires Firefox 128 for the
// sender origin/documentId checks the extension depends on.
const FIREFOX_EXTENSION_ID = "password-manager@nelszack.dev"; // Mirrors src/native_messaging.rs.
const FIREFOX_MIN_VERSION = "128.0";

function firefoxManifest(manifest) {
    const worker = manifest.background?.service_worker;
    if (typeof worker !== "string") throw new Error("Chrome manifest has no background service worker");
    const result = structuredClone(manifest);
    delete result.minimum_chrome_version;
    // Chrome derives the fixed extension ID from "key"; Firefox uses the gecko ID.
    delete result.key;
    // The worker is one bundled script, so the event page loads exactly it.
    result.background = { scripts: [worker] };
    result.browser_specific_settings = {
        gecko: { id: FIREFOX_EXTENSION_ID, strict_min_version: FIREFOX_MIN_VERSION },
    };
    return result;
}

module.exports = { FIREFOX_EXTENSION_ID, FIREFOX_MIN_VERSION, firefoxManifest };
