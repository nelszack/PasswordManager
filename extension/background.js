importScripts(
    "relay.js", "background_security.js", "background_state.js", "credential_prompt_state.js",
    "native_protocol.js", "pending_credentials.js", "background_native.js", "background_status.js",
    "background_pending.js", "background_pickers.js", "background_prompts.js", "background_router.js"
);

// Wire dependencies once; each service owns its maps and lifecycle rules.
const native = PasswordManagerBackgroundNative.create({
    chrome, protocol: PasswordManagerNativeProtocol, setTimeout, clearTimeout,
    onDisconnect: () => { pickers.invalidate(); prompts.invalidate(); }
});
const pendingCredentials = PasswordManagerBackgroundPending.create({
    chrome, security: PasswordManagerSecurity, records: PasswordManagerPendingCredentials, setTimeout
});
const pickers = PasswordManagerBackgroundPickers.create({
    chrome, security: PasswordManagerSecurity, protocol: PasswordManagerNativeProtocol,
    nativeRequest: native.request, crypto, setTimeout
});
const prompts = PasswordManagerBackgroundPrompts.create({
    chrome, security: PasswordManagerSecurity, promptState: PasswordManagerCredentialPrompt,
    pendingCredentials, nativeRequest: native.request, refreshStatus: () => status.refresh(), crypto, setTimeout
});
const manifest = chrome.runtime.getManifest();
const status = PasswordManagerBackgroundStatus.create({
    chrome, nativeRequest: native.request, state: PasswordManagerBackgroundState,
    version: manifest.version_name || manifest.version, setInterval,
    invalidate: () => { pickers.invalidate(); prompts.invalidate(); },
    cleanupExpired: () => router.cleanupExpired()
});
const router = PasswordManagerBackgroundRouter.create({
    chrome, security: PasswordManagerSecurity, relay: PasswordManagerRelay,
    nativeRequest: native.request, refreshStatus: status.refresh, pickers, prompts, pendingCredentials
});
chrome.windows.onRemoved.addListener(windowId => {
    if (!prompts.windowRemoved(windowId)) pickers.windowRemoved(windowId);
});
status.start();
