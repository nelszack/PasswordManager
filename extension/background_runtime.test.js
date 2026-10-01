const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

test("background worker starts, publishes status, and rejects untrusted credential requests", async () => {
    let messageListener;
    let nativeMessageListener;
    const badge = [];
    const event = callback => ({ addListener(listener) { callback?.(listener); } });
    const chrome = {
        action: {
            setBadgeText(value) { badge.push(value); },
            setBadgeBackgroundColor() {},
            setTitle() {}
        },
        alarms: { create() {}, onAlarm: event() },
        runtime: {
            id: "abcdefghijklmnopabcdefghijklmnop",
            lastError: null,
            getManifest: () => ({ version: "1.6", version_name: "0.1.0" }),
            getURL: value => `chrome-extension://abcdefghijklmnopabcdefghijklmnop/${value}`,
            onInstalled: event(),
            onStartup: event(),
            onMessage: event(listener => { messageListener = listener; }),
            sendMessage(_message, callback) { callback?.(); },
            connectNative() {
                return {
                    onMessage: event(listener => { nativeMessageListener = listener; }),
                    onDisconnect: event(),
                    postMessage(request) {
                        queueMicrotask(() => nativeMessageListener({
                            id: request.id, success: true, nativeVersion: "0.1.0",
                            data: "Status: unlocked\nVersion: 0.1.0"
                        }));
                    }
                };
            }
        },
        storage: {
            local: { set() {} },
            session: {
                get(_key, callback) { callback({}); },
                set(_value, callback) { callback?.(); },
                remove(_key, callback) { callback?.(); }
            }
        },
        tabs: { sendMessage() { return Promise.resolve(); } },
        windows: {
            create() { return Promise.resolve({ id: 1 }); },
            remove() { return Promise.resolve(); },
            onRemoved: event()
        }
    };
    const context = {
        chrome,
        PasswordManagerRelay: require("./relay.js"),
        PasswordManagerSecurity: require("./background_security.js"),
        PasswordManagerCredentialPrompt: require("./credential_prompt_state.js"),
        PasswordManagerBackgroundState: require("./background_state.js"),
        PasswordManagerNativeProtocol: require("./native_protocol.js"),
        PasswordManagerPendingCredentials: require("./pending_credentials.js"),
        importScripts() {},
        URL, Map, Set, Date, JSON, Promise, Error,
        setTimeout, clearTimeout, queueMicrotask,
        setInterval() { return 1; }
    };
    const filename = path.resolve(__dirname, "background.js");
    vm.runInNewContext(fs.readFileSync(filename, "utf8"), context, { filename });
    await new Promise(resolve => setImmediate(resolve));

    assert.equal(typeof messageListener, "function");
    assert.ok(badge.some(value => value.text === "U"));

    let response;
    assert.equal(messageListener(
        { action: "getCredentials" },
        { url: "file:///tmp/untrusted.html", tab: { id: 7 } },
        value => { response = value; }
    ), true);
    assert.equal(response.success, false);
    assert.equal(response.error, "Invalid page origin");
});
