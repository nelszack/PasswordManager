// Detection only asks the background to check. Request details and decisions
// stay in extension pages; verification numbers are never extracted from this page.
const PasswordManagerDuoDetection = require("./duo_detection.js");
module.exports.create = function create() {
    let activeSince = 0,
        checking = false,
        timer,
        disposed = false;
    let dirty = true,
        cached = false,
        scannedUrl;
    // Mutation bursts only invalidate; the existing poll interval coalesces reads.
    // Authorization requests always inspect the live rendered page instead.
    const observer = new MutationObserver(() => {
        dirty = true;
    });
    observer.observe(document, { subtree: true, childList: true, characterData: true, attributes: true });
    function active(fresh = false) {
        if (disposed || document.visibilityState === "hidden") return false;
        if (observer.takeRecords().length) dirty = true;
        if (fresh || dirty || scannedUrl !== location.href) {
            cached = PasswordManagerDuoDetection.challenge(document.body?.innerText, location.href);
            scannedUrl = location.href;
            dirty = false;
        }
        return cached;
    }
    function check() {
        if (disposed) return;
        clearTimeout(timer);
        if (!active()) {
            activeSince = 0;
            timer = setTimeout(check, 5000);
            return;
        }
        if (!activeSince) activeSince = Date.now();
        if (Date.now() - activeSince >= 5 * 60_000) return;
        if (checking) return;
        checking = true;
        chrome.runtime.sendMessage({ action: "observeDuoChallenge" }, () => {
            void chrome.runtime.lastError;
            checking = false;
            if (!disposed) timer = setTimeout(check, 5000);
        });
    }
    const listener = (message, _sender, respond) => {
        if (message.action === "getDuoChallengeState") respond({ active: active(true) });
    };
    chrome.runtime.onMessage.addListener(listener);
    const visibilityChanged = () => {
        dirty = true;
        check();
    };
    document.addEventListener("visibilitychange", visibilityChanged);
    const pagehide = () => clearTimeout(timer);
    window.addEventListener("pagehide", pagehide);
    check();
    return {
        dispose() {
            disposed = true;
            observer.disconnect();
            clearTimeout(timer);
            document.removeEventListener("visibilitychange", visibilityChanged);
            window.removeEventListener("pagehide", pagehide);
            chrome.runtime.onMessage.removeListener(listener);
        },
    };
};
