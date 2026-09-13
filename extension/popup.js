function sendMessage(message) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage(message, response => resolve(response || null));
    });
}

async function refreshStatus() {
    const status = await sendMessage({ action: "getStatus" }) || {
        native: false,
        running: false,
        locked: false
    };
    const dot = document.getElementById("statusDot");
    const text = document.getElementById("statusText");
    const lockButton = document.getElementById("lockBtn");

    if (!status.native) {
        dot.style.background = "#f59e0b";
        text.innerText = "Native host not installed";
        lockButton.disabled = true;
    } else if (!status.running) {
        dot.style.background = "#6b7280";
        text.innerText = "Server not running";
        lockButton.disabled = true;
    } else if (status.locked) {
        dot.style.background = "#ef4444";
        text.innerText = "Vault locked";
        lockButton.disabled = true;
    } else {
        dot.style.background = "#22c55e";
        text.innerText = "Vault unlocked";
        lockButton.disabled = false;
    }
}

document.addEventListener("DOMContentLoaded", refreshStatus);

document.getElementById("lockBtn").addEventListener("click", async () => {
    const response = await sendMessage({ action: "lockVault" });
    document.getElementById("output").innerText = response?.success
        ? response.data
        : response?.error || "Could not contact the native host";
    refreshStatus();
});
