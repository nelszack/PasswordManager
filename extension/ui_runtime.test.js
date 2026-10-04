const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

class FakeElement {
    constructor(id = "") {
        this.id = id;
        this.style = {};
        this.children = [];
        this.textContent = "";
        this.innerText = "";
        this.value = "";
        this.hidden = false;
        this.disabled = false;
        this.listeners = new Map();
    }
    addEventListener(type, listener) { this.listeners.set(type, listener); }
    dispatch(type, event = {}) { return this.listeners.get(type)?.({ preventDefault() {}, ...event }); }
    appendChild(child) { this.children.push(child); return child; }
    replaceChildren(...children) { this.children = children; }
    setAttribute() {}
    focus() { this.focused = true; }
    reportValidity() { return true; }
}

function environment(ids, responses, search = "") {
    const elements = Object.fromEntries(ids.map(id => [id, new FakeElement(id)]));
    const documentListeners = new Map();
    const messages = [];
    const document = {
        getElementById(id) { return elements[id]; },
        createElement() { return new FakeElement(); },
        addEventListener(type, listener) { documentListeners.set(type, listener); }
    };
    let runtimeListener;
    const context = {
        document,
        location: { search },
        URLSearchParams,
        Error,
        Promise,
        setTimeout,
        clearTimeout,
        console,
        window: { close() { context.closed = true; } },
        chrome: {
            runtime: {
                onMessage: { addListener(listener) { runtimeListener = listener; } },
                sendMessage(message, callback) {
                    messages.push(message);
                    callback(responses[message.action]);
                }
            },
            storage: {
                local: { get(_key, callback) { callback({ pmStatus: responses.pmStatus }); } }
            }
        }
    };
    return { context, elements, messages, documentListeners, runtimeListener: () => runtimeListener };
}

function execute(name, context) {
    const filename = path.resolve(__dirname, name);
    vm.runInNewContext(fs.readFileSync(filename, "utf8"), context, { filename });
}

test("popup runtime renders cached/live status and performs an explicit lock", async () => {
    const env = environment(["statusDot", "statusText", "lockBtn", "output"], {
        pmStatus: { native: true, running: true, locked: true },
        getStatus: { native: true, running: true, locked: false },
        lockVault: { success: true, data: "Vault locked." }
    });
    env.context.PasswordManagerPopupState = require("./popup_state.js");
    execute("popup.js", env.context);
    env.documentListeners.get("DOMContentLoaded")();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(env.elements.statusText.innerText, "Vault unlocked");
    assert.equal(env.elements.lockBtn.disabled, false);
    await env.elements.lockBtn.dispatch("click");
    assert.equal(env.elements.output.innerText, "Vault locked.");
    env.runtimeListener()({ action: "statusChanged", status: { native: true } });
    assert.equal(env.elements.statusText.innerText, "Server not running");
});

test("picker runtime discloses destinations and requires trusted, confirmed selections", async () => {
    for (const crossOrigin of [false, true]) {
        const item = crossOrigin ? { id: 2, name: "Visa" } : { id: 7, name: "Personal", username: "alice" };
        const origin = crossOrigin ? "https://embedded.example" : "https://example.com";
        const env = environment([
            "items", "status", "title", "cancel", "destination", "crossOriginWarning", "confirmCrossOrigin", "crossOriginText"
        ], {
            getSecurePickerData: {
                success: true, kind: crossOrigin ? "payment-card" : "login", origin,
                topOrigin: crossOrigin ? "https://shop.example" : origin, crossOrigin,
                items: [item]
            },
            completeSecurePicker: { success: true }
        }, crossOrigin ? "?token=card-token" : "?token=picker-token");
        env.context.PasswordManagerPickerState = require("./picker_state.js");
        execute("picker.js", env.context);
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(env.elements.title.textContent, crossOrigin ? "Choose payment card" : "Choose saved credentials");
        assert.equal(env.elements.destination.textContent, `Fill on: ${origin}`);
        assert.equal(env.elements.crossOriginWarning.hidden, !crossOrigin);
        assert.equal(env.elements.items.children.length, 1);
        env.elements.items.children[0].dispatch("click", { isTrusted: false });
        assert.equal(env.messages.length, 1, "synthetic selection is ignored");
        if (crossOrigin) {
            assert.match(env.elements.crossOriginText.textContent, /https:\/\/shop.example/);
            env.elements.items.children[0].dispatch("click", { isTrusted: true });
            await new Promise(resolve => setImmediate(resolve));
            assert.equal(env.messages.length, 1, "unconfirmed selection is ignored");
            assert.match(env.elements.status.textContent, /Confirm/);
            env.elements.confirmCrossOrigin.checked = true;
        }
        env.elements.items.children[0].dispatch("click", { isTrusted: true });
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(env.messages.at(-1).id, item.id);
        if (crossOrigin) assert.equal(env.messages.at(-1).confirmCrossOrigin, true);
        assert.equal(env.context.closed, true);
    }
});

test("credential prompt runtime renders metadata and submits only trusted actions", async () => {
    const env = environment([
        "credentials", "site", "status", "name", "username", "usernameLabel", "update", "cancel"
    ], {
        getCredentialPromptData: {
            success: true,
            data: {
                site: "https://example.com", message: "Save this login?", suggestedName: "Example",
                username: "alice", askForUsername: false, hasAccounts: true,
                updateTarget: { name: "Personal" }
            }
        },
        completeCredentialPrompt: { success: true }
    }, "?token=prompt-token");
    execute("credential_prompt.js", env.context);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(env.elements.credentials.hidden, false);
    assert.equal(env.elements.update.textContent, "Update Personal");
    env.elements.update.dispatch("click", { isTrusted: true });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(env.context.closed, true);
    assert.equal(env.messages.at(-1).selection.action, "update");
});
