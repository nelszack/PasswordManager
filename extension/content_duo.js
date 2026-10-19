// Detection only asks the background to check. Request details and decisions
// stay in extension pages; verification numbers are never extracted from this page.
const PasswordManagerDuoDetection = require("./duo_detection.js");
module.exports.create = function create() {
    let activeSince = 0, checking = false, timer, disposed = false;
    function active() {
        return document.visibilityState !== "hidden"
            && PasswordManagerDuoDetection.challenge(document.body?.innerText, location.href);
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
        if (message.action === "getDuoChallengeState") respond({ active: active() });
    };
    chrome.runtime.onMessage.addListener(listener);
    document.addEventListener("visibilitychange", check);
    window.addEventListener("pagehide", () => clearTimeout(timer));
    check();
    return { dispose() {
        disposed = true; clearTimeout(timer); document.removeEventListener("visibilitychange", check);
        chrome.runtime.onMessage.removeListener(listener);
    } };
};
