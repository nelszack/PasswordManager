function sendMessage(message) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage(message, response => resolve(response || null));
    });
}

function renderStatus(status) {
    const dot = document.getElementById("statusDot");
    const text = document.getElementById("statusText");
    const lockButton = document.getElementById("lockBtn");

    const presentation = PasswordManagerPopupState.presentation(status);
    dot.style.background = presentation.color;
    text.innerText = presentation.text;
    lockButton.disabled = !presentation.canLock;
    const hint = document.getElementById("nativeHint");
    if (hint) hint.textContent = !status.native
        ? "Open the vault manager for browser connection setup and troubleshooting."
        : !status.running ? "Run pm start, then open the vault manager to unlock your vault."
        : status.locked ? "Open the vault manager to unlock your vault."
        : "Use the key button beside a website’s login field to choose an account.";
}

async function refreshStatus() {
    const status = await sendMessage({ action: "getStatus" });
    if (status) renderStatus(status);
}

chrome.runtime.onMessage.addListener((message) => {
    if (message.action === "statusChanged" && message.status) {
        renderStatus(message.status);
    }
});

document.addEventListener("DOMContentLoaded", () => {
    chrome.storage.local.get("pmStatus", result => {
        if (result.pmStatus) renderStatus(result.pmStatus);
        refreshStatus();
    });
});

document.getElementById("lockBtn").addEventListener("click", async () => {
    const response = await sendMessage({ action: "lockVault" });
    document.getElementById("output").innerText = response?.success
        ? response.data
        : response?.error || "Could not contact the native host";
    await refreshStatus();
});
