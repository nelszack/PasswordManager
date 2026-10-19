importScripts(
    "command_contract.js", "background_security.js", "background_state.js", "credential_prompt_state.js",
    "native_protocol.js", "pending_credentials.js", "background_native.js", "background_status.js",
    "background_pending.js", "background_pickers.js", "background_prompts.js", "background_router.js",
    "duo_detection.js", "background_duo.js"
);

// Wire dependencies once; each service owns its maps and lifecycle rules.
const native = PasswordManagerBackgroundNative.create({
    chrome, protocol: PasswordManagerNativeProtocol, contract: PasswordManagerCommandContract, crypto, setTimeout, clearTimeout,
    onDisconnect: () => { pickers.invalidate(); prompts.invalidate(); duo.invalidate(); }
});
const pendingCredentials = PasswordManagerBackgroundPending.create({
    chrome, security: PasswordManagerSecurity, records: PasswordManagerPendingCredentials, setTimeout
});
const duo = PasswordManagerBackgroundDuo.create({
    chrome, security: PasswordManagerSecurity, protocol: PasswordManagerNativeProtocol,
    detection: PasswordManagerDuoDetection, nativeRequest: native.request,
    refreshStatus: () => status.refresh(), crypto, setTimeout
});
const pickers = PasswordManagerBackgroundPickers.create({
    chrome, security: PasswordManagerSecurity, protocol: PasswordManagerNativeProtocol,
    nativeRequest: native.request, crypto, setTimeout, onLoginSelected: duo.rememberLogin
});
const prompts = PasswordManagerBackgroundPrompts.create({
    chrome, security: PasswordManagerSecurity, promptState: PasswordManagerCredentialPrompt,
    pendingCredentials, matchesFilledLogin: pickers.matchesFilledLogin,
    nativeRequest: native.request, reconcile: native.reconcile, refreshStatus: () => status.refresh(), crypto, setTimeout,
    onLoginContext: duo.rememberLogin
});
const manifest = chrome.runtime.getManifest();
const status = PasswordManagerBackgroundStatus.create({
    chrome, nativeRequest: native.request, state: PasswordManagerBackgroundState,
    version: manifest.version_name || manifest.version, protocolVersion: PasswordManagerCommandContract.protocolVersion, setInterval, clearInterval, closeIdle: native.closeIdle,
    invalidate: () => { pickers.invalidate(); prompts.invalidate(); duo.invalidate(); },
    cleanupExpired: () => { pendingCredentials.cleanup().catch(() => {}); }
});
// Secret-bearing decisions do not survive a worker restart. Close their orphan views
// before accepting new requests; no plaintext decision data is restored from storage.
const startup = new Promise(resolve => {
    if (!chrome.windows.getAll) { resolve(); return; }
    chrome.windows.getAll({ populate: true }, windows => {
        const promptPaths = ["picker.html", "credential_prompt.html", "duo_prompt.html"].map(path => chrome.runtime.getURL(path));
        for (const window of windows || []) {
            if (window.tabs?.some(tab => promptPaths.some(path => tab.url?.split("?")[0] === path))) {
                chrome.windows.remove(window.id, () => void chrome.runtime.lastError);
            }
        }
        resolve();
    });
});
const router = PasswordManagerBackgroundRouter.create({
    chrome, security: PasswordManagerSecurity, contract: PasswordManagerCommandContract,
    nativeRequest: native.request, reconcile: native.reconcile, pendingOperations: native.unresolved, acknowledgeUnknown: native.acknowledgeUnknown, startup, refreshStatus: status.refresh, pickers, prompts, pendingCredentials, duo
});
chrome.windows.onRemoved.addListener(windowId => {
    if (!duo.windowRemoved(windowId) && !prompts.windowRemoved(windowId)) pickers.windowRemoved(windowId);
});
status.start();
