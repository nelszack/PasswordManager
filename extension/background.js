const NATIVE_HOST = "com.myproject.password_manager";
const REQUEST_TIMEOUT_MS = 7000;
const STATUS_POLL_ALARM = "status-poll";
const LIVE_STATUS_POLL_MS = 2000;

let nativePort = null;
let nextRequestId = 1;
const pendingRequests = new Map();
let cachedStatus = null;
let statusRefresh = null;

chrome.runtime.onInstalled.addListener(() => {
    startStatusMonitoring();
});

chrome.runtime.onStartup.addListener(() => {
    startStatusMonitoring();
});

function startStatusMonitoring() {
    chrome.alarms.create(STATUS_POLL_ALARM, { periodInMinutes: 1 });
    refreshStatus();
}

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === STATUS_POLL_ALARM) refreshStatus();
});

function closeNativePort(error) {
    const message = error || "Native messaging host disconnected";
    for (const pending of pendingRequests.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error(message));
    }
    pendingRequests.clear();
    nativePort = null;
}

function connectNativeHost() {
    if (nativePort) return nativePort;

    const port = chrome.runtime.connectNative(NATIVE_HOST);
    nativePort = port;
    port.onMessage.addListener((response) => {
        const pending = pendingRequests.get(response?.id);
        if (!pending) return;
        clearTimeout(pending.timer);
        pendingRequests.delete(response.id);
        pending.resolve(response);
    });
    port.onDisconnect.addListener(() => {
        const error = chrome.runtime.lastError?.message;
        if (nativePort === port) closeNativePort(error);
    });
    return port;
}

function nativeRequest(action, fields = {}) {
    return new Promise((resolve, reject) => {
        const id = nextRequestId++;
        const timer = setTimeout(() => {
            pendingRequests.delete(id);
            reject(new Error("Native messaging request timed out"));
        }, REQUEST_TIMEOUT_MS);
        pendingRequests.set(id, { resolve, reject, timer });

        try {
            connectNativeHost().postMessage({ id, action, ...fields });
        } catch (error) {
            clearTimeout(timer);
            pendingRequests.delete(id);
            reject(error);
        }
    });
}

function setBadge(status) {
    let text, color, title;
    if (!status.native) {
        text = "?";
        color = "#f59e0b";
        title = "Password Manager: native messaging host not installed";
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

function sameStatus(left, right) {
    return left?.native === right?.native
        && left?.running === right?.running
        && left?.locked === right?.locked
        && left?.error === right?.error;
}

function publishStatus(status) {
    setBadge(status);
    if (sameStatus(cachedStatus, status)) return;

    cachedStatus = status;
    chrome.storage.local.set({ pmStatus: status });
    chrome.runtime.sendMessage(
        { action: "statusChanged", status },
        () => void chrome.runtime.lastError
    );
}

async function serverStatus() {
    try {
        const response = await nativeRequest("status");
        if (!response.success) {
            return { native: true, running: false, locked: false, error: response.error };
        }
        return {
            native: true,
            running: true,
            locked: /\blocked\b/i.test(String(response.data))
        };
    } catch (error) {
        return { native: false, running: false, locked: false, error: error.message };
    }
}

function refreshStatus() {
    if (statusRefresh) return statusRefresh;
    statusRefresh = serverStatus()
        .then(status => {
            publishStatus(status);
            return status;
        })
        .finally(() => {
            statusRefresh = null;
        });
    return statusRefresh;
}

function sendAction(action, fields, sendResponse, refreshAfter = false) {
    nativeRequest(action, fields)
        .then(response => {
            sendResponse(response.success
                ? { success: true, data: response.data }
                : { success: false, error: response.error });
            if (refreshAfter) refreshStatus();
        })
        .catch(error => {
            sendResponse({ success: false, error: error.message });
            if (refreshAfter) refreshStatus();
        });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getStatus") {
        refreshStatus()
            .then(sendResponse)
            .catch(error => sendResponse({
                native: false,
                running: false,
                locked: false,
                error: error.message
            }));
        return true;
    }
    if (request.action === "getCredentials") {
        sendAction("getCredentials", { domain: request.domain }, sendResponse);
        return true;
    }
    if (request.action === "getAutofillItems") {
        sendAction("getAutofillItems", {}, sendResponse);
        return true;
    }
    if (request.action === "getTotp") {
        sendAction("getTotp", { entryId: request.id }, sendResponse);
        return true;
    }
    if (request.action === "saveCredentials") {
        sendAction("saveCredentials", {
            domain: request.domain,
            username: request.username,
            password: request.password,
            name: request.name
        }, sendResponse, true);
        return true;
    }
    if (request.action === "updateCredentials") {
        sendAction("updateCredentials", {
            domain: request.domain,
            username: request.username,
            password: request.password,
            name: request.name,
            entryId: request.id
        }, sendResponse, true);
        return true;
    }
    if (request.action === "lockVault") {
        sendAction("lock", {}, sendResponse, true);
        return true;
    }
    if (request.action === "relayToParent") {
        const tabId = sender.tab?.id;
        const frameId = sender.frameId;
        if (tabId != null && frameId != null) {
            chrome.tabs.get(tabId, (tab) => {
                if (chrome.runtime.lastError || !tab) return;
                if (frameId !== 0) {
                    chrome.tabs.sendMessage(tabId, request.data, { frameId: 0 });
                }
            });
        }
        sendResponse({ ok: true });
        return false;
    }
});

// A connected native-messaging port keeps the Manifest V3 worker alive,
// allowing state changes made by the CLI or auto-lock timer to reach the badge
// and an open popup promptly. The alarm above covers worker suspension/restart.
setInterval(refreshStatus, LIVE_STATUS_POLL_MS);
startStatusMonitoring();
