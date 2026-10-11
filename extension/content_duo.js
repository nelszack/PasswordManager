// Detection only asks the background to check. Request details and decisions
// stay in extension pages; verification numbers are never extracted from this page.
(function () {
    let activeSince = 0, checking = false, timer;
    function active() {
        return document.visibilityState !== "hidden"
            && PasswordManagerDuoDetection.challenge(document.body?.innerText, location.href);
    }
    function check() {
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
            timer = setTimeout(check, 5000);
        });
    }
    chrome.runtime.onMessage.addListener((message, _sender, respond) => {
        if (message.action === "getDuoChallengeState") respond({ active: active() });
    });
    document.addEventListener("visibilitychange", check);
    window.addEventListener("pagehide", () => clearTimeout(timer));
    check();
})();
