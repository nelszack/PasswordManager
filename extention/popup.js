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

document.getElementById("saveTokenBtn").addEventListener("click", async () => {
    const token = document.getElementById("tokenInput").value.trim();
    await saveToken(token);
    document.getElementById("output").innerText = token ? "Token saved" : "Token cleared";
});

document.addEventListener("DOMContentLoaded", async () => {
    document.getElementById("tokenInput").value = await loadToken();
});

document.getElementById("statusBtn").addEventListener("click", async () => {
    const result = await sendCommand("status");
    document.getElementById("output").innerText = result;
});

document.getElementById("getBtn").addEventListener("click", async () => {
    const site = prompt("Enter site name:");
    const result = await sendCommand("get", [site]);
    document.getElementById("output").innerText = result;
});

document.getElementById("lockBtn").addEventListener("click", async () => {
    const result = await sendCommand("lock", ["true"]);
    document.getElementById("output").innerText = result;
});
