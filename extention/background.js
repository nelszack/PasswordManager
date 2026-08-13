const SERVER_URL = "http://127.0.0.1:7878";

chrome.runtime.onInstalled.addListener(() => {
    console.log("Password Manager Extension Installed");
    chrome.alarms.create("status-poll", { periodInMinutes: 1 });
    refreshStatus();
});

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "status-poll") refreshStatus();
});

function loadToken() {
    return new Promise((resolve) => {
        chrome.storage.local.get("pmServerToken", (result) => {
            resolve(result.pmServerToken || "");
        });
    });
}

function setBadge(status) {
    let text, color, title;
    if (!status.token) {
        text = "?";
        color = "#f59e0b";
        title = "Password Manager: set the session token in the popup";
    } else if (!status.running) {
        text = "N";
        color = "#6b7280";
        title = "Password Manager: server not running";
    } else if (status.locked) {
        text = "L";
        color = "#ef4444";
        title = "Password Manager: vault locked";
    } else {
        text = "U";
        color = "#22c55e";
        title = "Password Manager: vault unlocked";
    }
    chrome.action.setBadgeText({ text });
    chrome.action.setBadgeBackgroundColor({ color });
    chrome.action.setTitle({ title });
}

async function refreshStatus() {
    const status = await serverStatus();
    setBadge(status);
    return status;
}

async function serverStatus() {
    const token = await loadToken();
    if (!token) {
        return { running: false, locked: false, token: false };
    }
    try {
        const res = await fetch(SERVER_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token,
                "Connection": "close"
            },
            body: JSON.stringify({ command: "status", extra_info: [] })
        });
        if (res.status === 401) {
            return { running: true, locked: false, token: false };
        }
        if (!res.ok) {
            return { running: false, locked: false, token: true };
        }
        const text = await res.text();
        return { running: true, locked: text.includes("Locked"), token: true };
    } catch (err) {
        return { running: false, locked: false, token: true };
    }
}

async function post(command, extra_info) {
    const token = await loadToken();
    if (!token) {
        return { error: "missing-token" };
    }
    const res = await fetch(SERVER_URL, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
            "Connection": "close"
        },
        body: JSON.stringify({ command, extra_info })
    });
    return { res };
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getStatus") {
        refreshStatus()
            .then(sendResponse)
            .catch(() => sendResponse({ running: false, locked: false, token: false }));
        return true;
    }
    if (request.action === "getCredentials") {
        post("get", [request.domain])
            .then(({ res, error }) => {
                if (error) return sendResponse({ success: false, error });
                return res.json().then(data => sendResponse({ success: true, data }));
            })
            .catch(err => sendResponse({ success: false, error: err.toString() }));
        return true;
    }
    if (request.action === "saveCredentials") {
        post("add", [request.domain, request.username, request.password, request.name])
            .then(({ res, error }) => {
                if (error) return sendResponse({ success: false, error });
                return res.text().then(data => sendResponse({ success: true, data }));
            })
            .catch(err => sendResponse({ success: false, error: err.toString() }));
        return true;
    }

    if (request.action === "updateCredentials") {
        post("update", [request.domain, request.username, request.password, request.name, request.id])
            .then(({ res, error }) => {
                if (error) return sendResponse({ success: false, error });
                return res.text().then(data => sendResponse({ success: true, data }));
            })
            .catch(err => sendResponse({ success: false, error: err.toString() }));
        return true;
    }
});
