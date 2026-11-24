// Chrome's service worker loads these here; Firefox's event page lists the same
// scripts in its generated manifest and has no importScripts.
if (typeof importScripts === "function") importScripts(
    "command_contract.js",
    "background_security.js",
    "background_state.js",
    "credential_prompt_state.js",
    "native_protocol.js",
    "pending_credentials.js",
    "background_native.js",
    "background_status.js",
    "background_pending.js",
    "background_windows.js",
    "background_pickers.js",
    "background_prompts.js",
    "background_router.js",
    "duo_detection.js",
    "background_duo.js",
    "background_passkeys.js",
    "background_popup.js"
);

// Wire dependencies once; each service owns its maps and lifecycle rules.
const native = PasswordManagerBackgroundNative.create({
    chrome,
    protocol: PasswordManagerNativeProtocol,
    contract: PasswordManagerCommandContract,
    crypto,
    setTimeout,
    clearTimeout,
    onDisconnect: () => {
        pickers.invalidate();
        prompts.invalidate();
        duo.invalidate();
        passkeys.invalidate();
        popup.invalidate();
    },
});
const pendingCredentials = PasswordManagerBackgroundPending.create({
    chrome,
    security: PasswordManagerSecurity,
    records: PasswordManagerPendingCredentials,
    setTimeout,
});
const duo = PasswordManagerBackgroundDuo.create({
    chrome,
    security: PasswordManagerSecurity,
    protocol: PasswordManagerNativeProtocol,
    detection: PasswordManagerDuoDetection,
    nativeRequest: native.request,
    // Duo pages report challenges every few seconds; reuse a recent status.
    refreshStatus: () => status.recent(10_000),
    crypto,
    setTimeout,
});
const pickers = PasswordManagerBackgroundPickers.create({
    chrome,
    security: PasswordManagerSecurity,
    protocol: PasswordManagerNativeProtocol,
    nativeRequest: native.request,
    crypto,
    setTimeout,
    onLoginSelected: duo.rememberLogin,
});
const prompts = PasswordManagerBackgroundPrompts.create({
    chrome,
    security: PasswordManagerSecurity,
    promptState: PasswordManagerCredentialPrompt,
    pendingCredentials,
    matchesFilledLogin: pickers.matchesFilledLogin,
    nativeRequest: native.request,
    reconcile: native.reconcile,
    refreshStatus: () => status.refresh(),
    crypto,
    setTimeout,
    onLoginContext: duo.rememberLogin,
});
const passkeys = PasswordManagerBackgroundPasskeys.create({
    chrome,
    security: PasswordManagerSecurity,
    nativeRequest: native.request,
    crypto,
    setTimeout,
});
const popup = PasswordManagerBackgroundPopup.create({
    chrome,
    security: PasswordManagerSecurity,
    protocol: PasswordManagerNativeProtocol,
    nativeRequest: native.request,
    crypto,
    setTimeout,
    rememberFilled: pickers.rememberFilled,
});
const manifest = chrome.runtime.getManifest();
const status = PasswordManagerBackgroundStatus.create({
    chrome,
    nativeRequest: native.request,
    subscribeStatus: native.subscribeStatus,
    state: PasswordManagerBackgroundState,
    version: manifest.version_name || manifest.version,
    protocolVersion: PasswordManagerCommandContract.protocolVersion,
    setInterval,
    clearInterval,
    closeIdle: native.closeIdle,
    invalidate: () => {
        pickers.invalidate();
        prompts.invalidate();
        duo.invalidate();
        passkeys.invalidate();
        popup.invalidate();
    },
    cleanupExpired: () => {
        pendingCredentials.cleanup().catch(() => {});
    },
});
// Secret-bearing decisions do not survive a worker restart. Close their orphan views
// before accepting new requests; no plaintext decision data is restored from storage.
const startup = new Promise(resolve => {
    if (!chrome.windows.getAll) {
        resolve();
        return;
    }
    chrome.windows.getAll({ populate: true }, windows => {
        const promptPaths = ["picker.html", "credential_prompt.html", "duo_prompt.html", "passkey_prompt.html"].map(path =>
            chrome.runtime.getURL(path)
        );
        for (const window of windows || []) {
            for (const tab of window.tabs || []) {
                if (promptPaths.some(path => tab.url?.split(/[?#]/)[0] === path)) {
                    // A restored decision can share a normal browser window with
                    // unrelated tabs. Removing its tab closes an otherwise empty popup.
                    chrome.tabs.remove(tab.id, () => void chrome.runtime.lastError);
                }
            }
        }
        resolve();
    });
});
const router = PasswordManagerBackgroundRouter.create({
    chrome,
    security: PasswordManagerSecurity,
    contract: PasswordManagerCommandContract,
    nativeRequest: native.request,
    reconcile: native.reconcile,
    pendingOperations: native.unresolved,
    acknowledgeUnknown: native.acknowledgeUnknown,
    startup,
    refreshStatus: status.refresh,
    pickers,
    prompts,
    pendingCredentials,
    duo,
    passkeys,
    popup,
});
chrome.windows.onRemoved.addListener(windowId => {
    if (!duo.windowRemoved(windowId) && !prompts.windowRemoved(windowId) && !passkeys.windowRemoved(windowId))
        pickers.windowRemoved(windowId);
});
status.start();
