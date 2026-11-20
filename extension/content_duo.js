// Detection only asks the background to check. Request details and decisions
// stay in extension pages; verification numbers are never extracted from this page.
const PasswordManagerDuoDetection = require("./duo_detection.js");
const inactive = { enabled: false, mutated() {}, dispose() {} };
module.exports.create = function create({
    flushMutations = () => {},
    alive = () => true,
    enabled = window === window.top || PasswordManagerDuoDetection.duoOrigin(location.href),
} = {}) {
    // Duo challenges appear in the top-level page or a Duo-hosted frame. Other
    // embedded frames (ads, widgets) never poll.
    if (!enabled) return inactive;
    let activeSince = 0,
        checking = false,
        timer = null,
        disposed = false;
    let dirty = true,
        cached = false,
        scannedUrl;
    // Mutations reach this module through the content observer and only mark the
    // cached result stale; the poll interval coalesces reads. Authorization
    // requests always inspect the live rendered page instead.
    function mutated() {
        dirty = true;
    }
    function scan() {
        const body = document.body;
        if (!body) return false;
        const url = location.href;
        // textContent needs no layout. Outside Duo's own pages a challenge always
        // names Duo, so skip the rendered-text read for every other page.
        if (!PasswordManagerDuoDetection.duoOrigin(url) && !/duo/i.test(body.textContent || "")) return false;
        return PasswordManagerDuoDetection.challenge(body.innerText, url);
    }
    function active(fresh = false) {
        if (disposed || document.visibilityState === "hidden") return false;
        flushMutations();
        if (fresh || dirty || scannedUrl !== location.href) {
            cached = scan();
            scannedUrl = location.href;
            dirty = false;
        }
        return cached;
    }
    function schedule() {
        clearTimeout(timer);
        timer = disposed || document.visibilityState === "hidden" ? null : setTimeout(check, 5000);
    }
    function check() {
        clearTimeout(timer);
        timer = null;
        // Hidden pages stop polling; becoming visible starts a new check.
        if (disposed || !alive() || document.visibilityState === "hidden") return;
        if (!active()) {
            activeSince = 0;
            schedule();
            return;
        }
        if (!activeSince) activeSince = Date.now();
        if (Date.now() - activeSince >= 5 * 60_000) return;
        if (checking) return;
        checking = true;
        chrome.runtime.sendMessage({ action: "observeDuoChallenge" }, () => {
            void chrome.runtime.lastError;
            checking = false;
            schedule();
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
    check();
    return {
        enabled: true,
        mutated,
        dispose() {
            disposed = true;
            clearTimeout(timer);
            timer = null;
            document.removeEventListener("visibilitychange", visibilityChanged);
            chrome.runtime.onMessage.removeListener(listener);
        },
    };
};
