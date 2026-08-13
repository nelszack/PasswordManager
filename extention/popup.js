const SERVER_URL = "http://127.0.0.1:7878";

function loadToken() {
    return new Promise((resolve) => {
        chrome.storage.local.get("pmServerToken", (result) => {
            resolve(result.pmServerToken || "");
        });
    });
}

function saveToken(token) {
    return new Promise((resolve) => {
        chrome.storage.local.set({ pmServerToken: token }, resolve);
    });
}

async function sendCommand(command, extra_info = []) {
    const token = await loadToken();
    if (!token) {
        return ["Server not reachable: set the session token first"];
    }
    try {
        const response = await fetch(SERVER_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token,
                "Connection": "close"
            },
            body: JSON.stringify({
                command: command,
                extra_info: extra_info
            })
        });

        const data = await response.json();
        return data;
    } catch (error) {
        console.log(error)
        return ["Server not reachable"]
    }
}

async function refreshStatus() {
    const status = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: "getStatus" }, (r) => {
            resolve(r || { running: false, locked: false, token: false });
        });
    });
    const dot = document.getElementById("statusDot");
    const text = document.getElementById("statusText");
    if (!status.token) {
        dot.style.background = "#f59e0b";
        text.innerText = "Set session token";
    } else if (!status.running) {
        dot.style.background = "#6b7280";
        text.innerText = "Server not running";
    } else if (status.locked) {
        dot.style.background = "#ef4444";
        text.innerText = "Vault locked";
    } else {
        dot.style.background = "#22c55e";
        text.innerText = "Vault unlocked";
    }
}

document.getElementById("saveTokenBtn").addEventListener("click", async () => {
    const token = document.getElementById("tokenInput").value.trim();
    await saveToken(token);
    document.getElementById("output").innerText = token ? "Token saved" : "Token cleared";
    refreshStatus();
});

document.addEventListener("DOMContentLoaded", async () => {
    document.getElementById("tokenInput").value = await loadToken();
    refreshStatus();
});

document.getElementById("lockBtn").addEventListener("click", async () => {
    const result = await sendCommand("lock", ["true"]);
    document.getElementById("output").innerText = result;
    refreshStatus();
});
