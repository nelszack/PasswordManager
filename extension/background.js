importScripts("relay.js", "background_security.js", "credential_prompt_state.js");

const NATIVE_HOST = "com.myproject.password_manager";
const REQUEST_TIMEOUT_MS = 7000;
const STATUS_POLL_ALARM = "status-poll";
const LIVE_STATUS_POLL_MS = 2000;

let nativePort = null;
let nextRequestId = 1;
const pendingRequests = new Map();
const pendingRelays = new Map();
const pendingPickers = new Map();
const pickerWindows = new Map();
const pendingCredentialPrompts = new Map();
const credentialPromptWindows = new Map();
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

function setPendingCredentials(request, sender, sendResponse) {
    const key = PasswordManagerSecurity.pendingStorageKey(sender);
    const domain = PasswordManagerSecurity.senderOrigin(sender);
    const pending = request.pending;
    if (!key || !domain || !pending || typeof pending.password !== "string") {
        sendResponse({ success: false, error: "Invalid pending credentials" });
        return;
    }
    chrome.storage.session.set({
        [key]: {
            domain,
            username: String(pending.username || ""),
            password: pending.password,
            accountName: String(pending.accountName || ""),
            hasAccounts: Boolean(pending.hasAccounts),
            time: Date.now()
        }
    }, () => sendResponse(chrome.runtime.lastError
        ? { success: false, error: chrome.runtime.lastError.message }
        : { success: true }));
}

function consumePendingCredentials(sender, sendResponse) {
    const key = PasswordManagerSecurity.pendingStorageKey(sender);
    const domain = PasswordManagerSecurity.senderOrigin(sender);
    if (!key || !domain) {
        sendResponse({ success: false, error: "Invalid page origin" });
        return;
    }
    chrome.storage.session.get(key, result => {
        const error = chrome.runtime.lastError?.message;
        const pending = result?.[key] || null;
        chrome.storage.session.remove(key, () => void chrome.runtime.lastError);
        if (error) sendResponse({ success: false, error });
        else if (pending?.domain === domain && Date.now() - pending.time < 60_000) {
            sendResponse({ success: true, pending });
        } else {
            sendResponse({ success: true, pending: null });
        }
    });
}

function clearPendingCredentials(sender, sendResponse) {
    const key = PasswordManagerSecurity.pendingStorageKey(sender);
    if (!key) {
        sendResponse({ success: false, error: "Invalid tab" });
        return;
    }
    chrome.storage.session.remove(key, () => sendResponse(chrome.runtime.lastError
        ? { success: false, error: chrome.runtime.lastError.message }
        : { success: true }));
}

function sendTotpForPage(request, sender, sendResponse) {
    const domain = PasswordManagerSecurity.senderOrigin(sender);
    if (!domain || !Number.isSafeInteger(request.id) || request.id <= 0) {
        sendResponse({ success: false, error: "Invalid TOTP request" });
        return;
    }
    nativeRequest("getCredentials", { domain })
        .then(response => {
            if (!response.success) throw new Error(response.error || "Credentials unavailable");
            let accounts;
            try {
                accounts = JSON.parse(response.data);
            } catch (_) {
                throw new Error("Invalid credential response");
            }
            if (!PasswordManagerSecurity.totpEntryAllowed(accounts, request.id)) {
                throw new Error("TOTP entry is not authorized for this site");
            }
            return nativeRequest("getTotp", { entryId: request.id });
        })
        .then(response => sendResponse(response.success
            ? { success: true, data: response.data }
            : { success: false, error: response.error }))
        .catch(error => sendResponse({ success: false, error: error.message }));
}

function parseNativeItems(response) {
    if (!response?.success) throw new Error(response?.error || "Vault items unavailable");
    const items = JSON.parse(response.data);
    if (!Array.isArray(items)) throw new Error("Invalid vault item response");
    return items;
}

function pickerSenderAllowed(sender) {
    return PasswordManagerSecurity.securePickerSender(
        sender,
        chrome.runtime.id,
        chrome.runtime.getURL("picker.html")
    );
}

async function loadSecurePickerItems(kind, domain) {
    let items;
    if (kind === "login" || kind === "totp") {
        items = parseNativeItems(await nativeRequest("getCredentials", { domain }));
        if (kind === "totp") items = items.filter(item => item?.has_totp === true);
    } else {
        items = parseNativeItems(await nativeRequest("getAutofillItems"));
        items = items.filter(item => item?.kind === kind);
    }
    const summaries = items.map(item => ({
        id: item.id,
        name: String(item.name || ""),
        username: String(item.username || ""),
        kind
    })).filter(item => Number.isSafeInteger(item.id) && item.id > 0);
    return { items, summaries };
}

async function openSecurePicker(request, sender) {
    const domain = PasswordManagerSecurity.senderOrigin(sender);
    const tabId = sender?.tab?.id;
    const frameId = sender?.frameId;
    const kind = request?.kind;
    if (!domain || !Number.isInteger(tabId) || !Number.isInteger(frameId)
        || !["login", "totp", "payment-card", "identity"].includes(kind)) {
        throw new Error("Invalid secure picker request");
    }

    const token = crypto.randomUUID();
    pendingPickers.set(token, {
        tabId, frameId, kind,
        items: [],
        summaries: [],
        loading: true,
        error: null,
        expiresAt: Date.now() + 60_000
    });

    return new Promise((resolve, reject) => {
        chrome.windows.create({
            url: chrome.runtime.getURL(`picker.html?token=${encodeURIComponent(token)}`),
            type: "popup",
            width: 380,
            height: 480,
            focused: true
        }, window => {
            const error = chrome.runtime.lastError?.message;
            if (error || !window?.id) {
                pendingPickers.delete(token);
                reject(new Error(error || "Could not open secure picker"));
                return;
            }
            pickerWindows.set(window.id, token);
            loadSecurePickerItems(kind, domain)
                .then(({ items, summaries }) => {
                    const pending = pendingPickers.get(token);
                    if (!pending) return;
                    pending.items = items;
                    pending.summaries = summaries;
                    pending.loading = false;
                })
                .catch(loadError => {
                    const pending = pendingPickers.get(token);
                    if (!pending) return;
                    pending.loading = false;
                    pending.error = loadError.message || "Vault items unavailable";
                });
            setTimeout(() => {
                if (!pendingPickers.has(token)) return;
                pendingPickers.delete(token);
                chrome.windows.remove(window.id, () => void chrome.runtime.lastError);
            }, 60_000);
            resolve({ success: true, token });
        });
    });
}

function credentialPromptSenderAllowed(sender) {
    return PasswordManagerSecurity.securePickerSender(
        sender,
        chrome.runtime.id,
        chrome.runtime.getURL("credential_prompt.html")
    );
}

function notifyCredentialPrompt(token, pending, action) {
    chrome.tabs.sendMessage(
        pending.tabId,
        { action: "credentialPromptResult", token, result: { action } },
        { frameId: pending.frameId },
        () => void chrome.runtime.lastError
    );
}

function discardCredentialPrompt(token, action = "cancel", closeWindow = true) {
    const pending = pendingCredentialPrompts.get(token);
    if (!pending) return;
    pendingCredentialPrompts.delete(token);
    notifyCredentialPrompt(token, pending, action);
    if (!Number.isInteger(pending.windowId)) return;
    credentialPromptWindows.delete(pending.windowId);
    if (closeWindow) {
        chrome.windows.remove(pending.windowId, () => void chrome.runtime.lastError);
    }
}

async function openCredentialPrompt(request, sender) {
    const domain = PasswordManagerSecurity.senderOrigin(sender);
    const tabId = sender?.tab?.id;
    const frameId = sender?.frameId;
    const username = request?.username;
    const password = request?.password;
    if (!domain || !Number.isInteger(tabId) || !Number.isInteger(frameId)
        || typeof username !== "string" || username.length > 4096
        || typeof password !== "string" || !password || password.length > 64 * 1024
        || /[\0\r\n]/.test(username) || /[\0\r\n]/.test(password)) {
        throw new Error("Invalid credential prompt request");
    }

    const accounts = parseNativeItems(await nativeRequest("getCredentials", { domain }));
    const exactMatch = PasswordManagerCredentialPrompt.hasExactMatch(
        accounts, username, password
    );
    if (exactMatch) return { success: true, matched: true };

    const token = crypto.randomUUID();
    const pending = {
        tabId,
        frameId,
        domain,
        username,
        password,
        data: PasswordManagerCredentialPrompt.describe(accounts, username, domain),
        expiresAt: Date.now() + 2 * 60_000,
        windowId: null,
        completing: false
    };
    pendingCredentialPrompts.set(token, pending);

    return new Promise((resolve, reject) => {
        chrome.windows.create({
            url: chrome.runtime.getURL(
                `credential_prompt.html?token=${encodeURIComponent(token)}`
            ),
            type: "popup",
            width: 400,
            height: 430,
            focused: true
        }, window => {
            const error = chrome.runtime.lastError?.message;
            if (error || !window?.id) {
                pendingCredentialPrompts.delete(token);
                reject(new Error(error || "Could not open credential prompt"));
                return;
            }
            pending.windowId = window.id;
            credentialPromptWindows.set(window.id, token);
            setTimeout(() => discardCredentialPrompt(token), 2 * 60_000);
            resolve({ success: true, token });
        });
    });
}

async function completeCredentialPrompt(request, sender) {
    if (!credentialPromptSenderAllowed(sender)) throw new Error("Invalid credential prompt sender");
    const pending = pendingCredentialPrompts.get(request?.token);
    if (!pending || pending.expiresAt <= Date.now()) {
        discardCredentialPrompt(request?.token);
        throw new Error("Credential prompt expired");
    }
    if (pending.completing) throw new Error("Credential operation is already in progress");
    const operation = PasswordManagerCredentialPrompt.operation(pending, request.selection);
    if (operation.action === "cancel") {
        discardCredentialPrompt(request.token, "cancel", false);
        return { success: true };
    }

    const nativeAction = operation.action === "update" ? "updateCredentials" : "saveCredentials";
    pending.completing = true;
    let response;
    try {
        response = await nativeRequest(nativeAction, operation.fields);
        if (!response.success) throw new Error(response.error || "Could not save credentials");
    } catch (error) {
        pending.completing = false;
        throw error;
    }
    discardCredentialPrompt(request.token, operation.action, false);
    refreshStatus();
    return { success: true };
}

async function completeSecurePicker(request, sender) {
    if (!pickerSenderAllowed(sender)) throw new Error("Invalid picker sender");
    const pending = pendingPickers.get(request?.token);
    if (!pending || pending.expiresAt <= Date.now()) {
        pendingPickers.delete(request?.token);
        throw new Error("Secure picker expired");
    }
    if (request.cancel === true) {
        pendingPickers.delete(request.token);
        return { success: true };
    }
    if (pending.loading) throw new Error("Secure picker is still loading");
    if (pending.error) throw new Error(pending.error);
    if (!Number.isSafeInteger(request.id) || request.id <= 0) {
        throw new Error("Invalid picker selection");
    }
    const selected = pending.items.find(item => item?.id === request.id);
    if (!selected) throw new Error("Picker selection is unavailable");

    let payload;
    if (pending.kind === "login") {
        payload = selected;
    } else if (pending.kind === "totp") {
        const response = await nativeRequest("getTotp", { entryId: selected.id });
        if (!response.success) throw new Error(response.error || "TOTP unavailable");
        payload = response.data;
    } else {
        const response = await nativeRequest("getAutofillItem", { entryId: selected.id });
        if (!response.success) throw new Error(response.error || "Autofill item unavailable");
        payload = JSON.parse(response.data);
    }
    pendingPickers.delete(request.token);
    await chrome.tabs.sendMessage(
        pending.tabId,
        { action: "securePickerResult", token: request.token, payload },
        { frameId: pending.frameId }
    );
    return { success: true };
}

chrome.windows.onRemoved.addListener(windowId => {
    const credentialToken = credentialPromptWindows.get(windowId);
    if (credentialToken) {
        credentialPromptWindows.delete(windowId);
        const pending = pendingCredentialPrompts.get(credentialToken);
        if (pending?.completing) {
            pending.windowId = null;
            return;
        }
        discardCredentialPrompt(credentialToken, "cancel", false);
        return;
    }
    const token = pickerWindows.get(windowId);
    if (!token) return;
    pickerWindows.delete(windowId);
    pendingPickers.delete(token);
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "openCredentialPrompt") {
        openCredentialPrompt(request, sender)
            .then(sendResponse)
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true;
    }
    if (request.action === "getCredentialPromptData") {
        if (!credentialPromptSenderAllowed(sender)) {
            sendResponse({ success: false, error: "Invalid credential prompt sender" });
        } else {
            const pending = pendingCredentialPrompts.get(request.token);
            sendResponse(pending && pending.expiresAt > Date.now()
                ? { success: true, data: pending.data }
                : { success: false, error: "Credential prompt expired" });
        }
        return true;
    }
    if (request.action === "completeCredentialPrompt") {
        completeCredentialPrompt(request, sender)
            .then(sendResponse)
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true;
    }
    if (request.action === "openSecurePicker") {
        openSecurePicker(request, sender)
            .then(sendResponse)
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true;
    }
    if (request.action === "getSecurePickerData") {
        if (!pickerSenderAllowed(sender)) {
            sendResponse({ success: false, error: "Invalid picker sender" });
        } else {
            const pending = pendingPickers.get(request.token);
            sendResponse(pending && pending.expiresAt > Date.now()
                ? {
                    success: true,
                    kind: pending.kind,
                    items: pending.summaries,
                    loading: pending.loading,
                    error: pending.error
                }
                : { success: false, error: "Secure picker expired" });
        }
        return true;
    }
    if (request.action === "completeSecurePicker") {
        completeSecurePicker(request, sender)
            .then(sendResponse)
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true;
    }
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
        const domain = PasswordManagerSecurity.senderOrigin(sender);
        if (!domain) sendResponse({ success: false, error: "Invalid page origin" });
        else sendAction("getCredentials", { domain }, sendResponse);
        return true;
    }
    if (request.action === "saveCredentials") {
        const domain = PasswordManagerSecurity.senderOrigin(sender);
        if (!domain) sendResponse({ success: false, error: "Invalid page origin" });
        else sendAction("saveCredentials", {
            domain,
            username: request.username,
            password: request.password,
            name: request.name
        }, sendResponse, true);
        return true;
    }
    if (request.action === "updateCredentials") {
        const domain = PasswordManagerSecurity.senderOrigin(sender);
        if (!domain) sendResponse({ success: false, error: "Invalid page origin" });
        else sendAction("updateCredentials", {
            domain,
            username: request.username,
            password: request.password,
            name: request.name,
            entryId: request.id
        }, sendResponse, true);
        return true;
    }
    if (request.action === "getRelayedCredentials") {
        const relay = PasswordManagerRelay.authorizeCredentialRequest(
            request, sender, pendingRelays
        );
        if (!relay) sendResponse({ success: false, error: "Invalid credential relay" });
        else sendAction("getCredentials", { domain: relay.domain }, sendResponse);
        return true;
    }
    if (request.action === "saveRelayedCredentials"
        || request.action === "updateRelayedCredentials") {
        const relay = PasswordManagerRelay.authorizeCredentialRequest(
            request, sender, pendingRelays, true
        );
        if (!relay) {
            sendResponse({ success: false, error: "Invalid credential relay" });
        } else {
            const update = request.action === "updateRelayedCredentials";
            sendAction(update ? "updateCredentials" : "saveCredentials", {
                domain: relay.domain,
                username: request.username,
                password: request.password,
                name: request.name,
                ...(update ? { entryId: request.id } : {})
            }, sendResponse, true);
        }
        return true;
    }
    if (request.action === "setPendingCredentials") {
        setPendingCredentials(request, sender, sendResponse);
        return true;
    }
    if (request.action === "consumePendingCredentials") {
        consumePendingCredentials(sender, sendResponse);
        return true;
    }
    if (request.action === "clearPendingCredentials") {
        clearPendingCredentials(sender, sendResponse);
        return true;
    }
    if (request.action === "lockVault") {
        sendAction("lock", {}, sendResponse, true);
        return true;
    }
    if (request.action === "relayToParent") {
        const route = PasswordManagerRelay.requestRoute(request.data, sender);
        if (route) {
            pendingRelays.set(
                PasswordManagerRelay.relayKey(route.tabId, request.data.token),
                {
                    sourceFrameId: sender.frameId,
                    domain: request.data.domain,
                    expiresAt: Date.now() + 5 * 60_000
                }
            );
            chrome.tabs.sendMessage(
                route.tabId,
                route.message,
                { frameId: route.frameId },
                () => void chrome.runtime.lastError
            );
            sendResponse({ ok: true });
        } else {
            sendResponse({ ok: false });
        }
        return false;
    }
    if (request.action === "relayLoginResult") {
        const route = PasswordManagerRelay.resultRoute(request, sender);
        if (route) {
            chrome.tabs.sendMessage(
                route.tabId,
                route.message,
                { frameId: route.frameId },
                () => void chrome.runtime.lastError
            );
            sendResponse({ ok: true });
        } else {
            sendResponse({ ok: false });
        }
        return false;
    }
});

// A connected native-messaging port keeps the Manifest V3 worker alive,
// allowing state changes made by the CLI or auto-lock timer to reach the badge
// and an open popup promptly. The alarm above covers worker suspension/restart.
setInterval(refreshStatus, LIVE_STATUS_POLL_MS);
startStatusMonitoring();
