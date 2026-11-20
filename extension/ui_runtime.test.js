const test = require("node:test");
const assert = require("node:assert/strict");
const { loadScript } = require("./test_harness.cjs");

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
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    setAttribute() {}
    focus() { this.focused = true; }
    reportValidity() { return true; }
}

function environment(ids, responses, search = "") {
    const elements = Object.fromEntries(ids.map(id => [id, new FakeElement(id)]));
    const documentListeners = new Map();
    const messages = [];
    const stored = { pmStatus: responses.pmStatus, ...responses.storage };
    const clock = { now: 1_000_000 };
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
                local: {
                    get(_key, callback) { callback({ ...stored }); },
                    set(values) { Object.assign(stored, values); }
                }
            }
        },
        crypto: globalThis.crypto,
        Date: { now: () => clock.now },
        navigator: { clipboard: { async writeText(value) {
            if (responses.clipboardFails) throw new Error("denied");
            context.copied = value;
        } } }
    };
    return {
        context, elements, messages, stored, documentListeners, runtimeListener: () => runtimeListener,
        advance(ms = 1000) { clock.now += ms; }
    };
}

function execute(name, context) {
    loadScript("ui_transport.js", context);
    loadScript(name, context);
}

const settle = () => new Promise(resolve => setImmediate(resolve));

async function popupEnvironment(responses) {
    const env = environment([
        "statusDot", "statusText", "lockBtn", "openDesktopBtn", "output", "nativeHint", "recovery", "operation",
        "reviewOperation", "unknownReview", "inspected", "acknowledgeOperation", "genValue", "genNew", "genCopy",
        "genLength", "genLengthValue", "genSymbols", "genPassphrase", "neverSave", "neverCount",
        "neverList"
    ], responses);
    env.context.PasswordManagerPopupState = require("./popup_state.js");
    env.context.PasswordManagerGenerator = require("./password_generator.js");
    execute("popup.js", env.context);
    env.documentListeners.get("DOMContentLoaded")();
    await settle();
    return env;
}

test("popup runtime renders cached/live status and performs an explicit lock", async () => {
    const env = await popupEnvironment({
        pmStatus: { native: true, running: true, locked: true },
        getStatus: { native: true, running: true, locked: false },
        lockVault: { success: true, data: "Vault locked." }
    });
    assert.equal(env.elements.statusText.innerText, "Vault unlocked");
    assert.equal(env.elements.lockBtn.disabled, false);
    await env.elements.lockBtn.dispatch("click");
    assert.equal(env.elements.output.innerText, "Vault locked.");
    env.runtimeListener()({ action: "statusChanged", status: { native: true } });
    assert.equal(env.elements.statusText.innerText, "Desktop app not running");
    assert.match(env.elements.nativeHint.textContent, /desktop app/);
    env.runtimeListener()({ action: "statusChanged", status: { native: false } });
    assert.match(env.elements.nativeHint.textContent, /browser integration/);
    env.runtimeListener()({ action: "statusChanged", status: { native: true, running: true, locked: true } });
    assert.match(env.elements.nativeHint.textContent, /Unlock/);
    env.runtimeListener()({ action: "statusChanged", status: { native: true, running: true, locked: false } });
    assert.match(env.elements.nativeHint.textContent, /key button/);
});

// Picker data defaults to a same-origin login; tests override only what differs.
async function pickerEnvironment(items, data = {}, search = "?token=picker-token") {
    const env = environment([
        "items", "status", "title", "cancel", "destination", "crossOriginWarning", "confirmCrossOrigin",
        "crossOriginText", "search", "recovery", "retry"
    ], {
        getSecurePickerData: { success: true, kind: "login", origin: "https://example.com",
            topOrigin: "https://example.com", items, ...data },
        completeSecurePicker: { success: true }
    }, search);
    env.context.PasswordManagerPickerState = require("./picker_state.js");
    execute("picker.js", env.context);
    await settle();
    return env;
}

test("picker runtime discloses destinations and requires trusted, confirmed selections", async () => {
    for (const crossOrigin of [false, true]) {
        const item = crossOrigin ? { id: 2, name: "Visa" } : { id: 7, name: "Personal", username: "alice" };
        const origin = crossOrigin ? "https://embedded.example" : "https://example.com";
        const env = await pickerEnvironment([item], crossOrigin ? {
            kind: "payment-card", origin, topOrigin: "https://shop.example", crossOrigin
        } : {}, crossOrigin ? "?token=card-token" : "?token=picker-token");
        assert.equal(env.elements.title.textContent, crossOrigin ? "Choose a payment card" : "Choose a login");
        assert.equal(env.elements.destination.textContent, `Fill on: ${origin}`);
        assert.equal(env.elements.crossOriginWarning.hidden, !crossOrigin);
        assert.equal(env.elements.items.children.length, 1);
        assert.equal(env.elements.search.hidden, true, "a single item needs no search");
        assert.notEqual(env.elements.items.children[0].focused, true, "no account is pre-focused");
        assert.equal(env.elements.items.children[0].disabled, true, "items start disabled");
        await new Promise(resolve => setTimeout(resolve, 550));
        assert.equal(env.elements.items.children[0].disabled, false, "items enable after the guard");
        env.elements.items.children[0].dispatch("click", { isTrusted: true });
        await settle();
        assert.equal(env.messages.length, 1, "a click right after opening is ignored");
        env.advance();
        env.elements.items.children[0].dispatch("click", { isTrusted: false });
        assert.equal(env.messages.length, 1, "synthetic selection is ignored");
        if (crossOrigin) {
            assert.match(env.elements.crossOriginText.textContent, /https:\/\/shop.example/);
            env.elements.items.children[0].dispatch("click", { isTrusted: true });
            await settle();
            assert.equal(env.messages.length, 1, "unconfirmed selection is ignored");
            assert.match(env.elements.status.textContent, /Confirm/);
            env.elements.confirmCrossOrigin.checked = true;
        }
        env.elements.items.children[0].dispatch("click", { isTrusted: true });
        await settle();
        assert.equal(env.messages.at(-1).id, item.id);
        if (crossOrigin) assert.equal(env.messages.at(-1).confirmCrossOrigin, true);
        assert.equal(env.context.closed, true);
    }
});

// Each view gets a fresh document, worker transport, and response map. Recovery
// scenarios replace only their response; metadata setup stays identical.
async function credentialPromptEnvironment(responses = {}) {
    Object.assign(responses, {
        getCredentialPromptData: { success: true, data: {
            site: "https://example.com", message: "Save this login?", suggestedName: "Example",
            username: "alice", askForUsername: false, hasAccounts: true, updateTarget: { name: "Personal" }
        } },
        completeCredentialPrompt: { success: true },
        ...responses
    });
    const env = environment([
        "credentials", "site", "status", "name", "username", "usernameLabel", "updateNote", "reviewOutcome", "add", "update", "cancel", "never"
    ], responses, "?token=prompt-token");
    execute("credential_prompt.js", env.context);
    await settle();
    return env;
}

test("credential prompt runtime renders metadata and submits only trusted actions", async () => {
    const env = await credentialPromptEnvironment();
    assert.equal(env.elements.credentials.hidden, false);
    assert.equal(env.elements.update.textContent, "Update “Personal”");
    assert.equal(env.elements.updateNote.hidden, true);
    env.elements.update.dispatch("click", { isTrusted: true });
    await settle();
    assert.equal(env.context.closed, true);
    assert.equal(env.messages.at(-1).selection.action, "update");
});

test("credential prompt explains that updating another account keeps its username", async () => {
    const env = await credentialPromptEnvironment({
        getCredentialPromptData: { success: true, data: {
            site: "https://example.com", message: "No saved account has this username.", suggestedName: "Alice",
            username: "bob", askForUsername: false, hasAccounts: true,
            updateTarget: { name: "Alice", username: "alice" },
            updateNote: "Updating “Alice” changes only its password and keeps the username “alice”."
        } }
    });
    assert.equal(env.elements.updateNote.hidden, false);
    assert.match(env.elements.updateNote.textContent, /keeps the username “alice”/);
    assert.equal(env.elements.username.hidden, true);
});

test("credential prompt disables writes after an uncertain save and still allows dismissal", async () => {
    const responses = {
        getCredentialPromptData: { success: true, data: { site: "https://example.com", message: "Save?", suggestedName: "Example", username: "alice", hasAccounts: true } },
        completeCredentialPrompt: { success: false, error: "Save may still complete. Review the vault.", uncertain: true }
    };
    const env = await credentialPromptEnvironment(responses);
    env.elements.credentials.dispatch("submit", { isTrusted: true }); await settle();
    assert.equal(env.elements.add.disabled, true);
    assert.equal(env.elements.update.disabled, true);
    assert.match(env.elements.status.textContent, /may still complete/);
    env.elements.update.dispatch("click", { isTrusted: true }); await settle();
    assert.equal(env.messages.filter(message => message.action === "completeCredentialPrompt").length, 1);
    responses.completeCredentialPrompt = { success: true };
    env.elements.cancel.dispatch("click", { isTrusted: true }); await settle();
    assert.equal(env.messages.at(-1).selection.action, "cancel");
    assert.equal(env.context.closed, true);
});

test("credential prompt outcome review reports each save state without retrying", async () => {
    const responses = {};
    const env = await credentialPromptEnvironment(responses);
    const review = async () => {
        env.elements.reviewOutcome.dispatch("click", { isTrusted: true });
        await settle();
    };
    env.elements.reviewOutcome.dispatch("click", { isTrusted: false });
    assert.equal(env.messages.some(message => message.action === "reviewCredentialPrompt"), false);
    for (const [state, expected] of [
        ["pending", /still running/],
        ["unknown", /outcome is unknown/],
        ["committed_durability_unknown", /durability is uncertain/],
    ]) {
        responses.reviewCredentialPrompt = { success: true, data: { state } };
        await review();
        assert.match(env.elements.status.textContent, expected, state);
        assert.notEqual(env.context.closed, true, state);
    }
    assert.equal(env.elements.reviewOutcome.hidden, true);
    responses.reviewCredentialPrompt = { success: false, error: "Review unavailable" };
    await review();
    assert.match(env.elements.status.textContent, /Review unavailable/);
    responses.reviewCredentialPrompt = { success: true, data: { state: "committed" } };
    await review();
    assert.equal(env.context.closed, true);
    assert.equal(env.messages.some(message => message.action === "completeCredentialPrompt"), false);
});

test("popup requires a reviewed unknown outcome and explicit inspection without replaying a save", async () => {
    const responses = {
        getStatus: { native: true, running: true, locked: false, pendingOperations: [{ operationId: "save-one", action: "saveCredentials" }] },
        reconcileOperation: { success: true, data: { operationId: "save-one", state: "pending" } },
        acknowledgeUnknownOperation: { success: true }
    };
    const env = await popupEnvironment(responses);
    env.elements.operation.value = "save-one";
    await env.elements.reviewOperation.dispatch("click");
    assert.equal(env.elements.unknownReview.hidden, true);
    env.elements.inspected.checked = true;
    await env.elements.acknowledgeOperation.dispatch("click");
    assert.equal(env.messages.some(message => message.action === "acknowledgeUnknownOperation"), false);
    responses.reconcileOperation.data.state = "unknown";
    await env.elements.reviewOperation.dispatch("click");
    assert.equal(env.elements.unknownReview.hidden, false);
    assert.equal(env.elements.inspected.checked, false);
    env.elements.inspected.checked = true;
    await env.elements.inspected.dispatch("change", { target: env.elements.inspected });
    responses.getStatus.pendingOperations = [];
    await env.elements.acknowledgeOperation.dispatch("click");
    assert.equal(env.elements.recovery.hidden, true);
    assert.equal(env.messages.filter(message => message.action === "acknowledgeUnknownOperation").length, 1);
    assert.equal(env.messages.some(message => ["saveCredentials", "updateCredentials"].includes(message.action)), false);
});

test("popup opens the desktop while disconnected and reports launch errors", async () => {
    for (const response of [{ success: true }, { success: false, error: "Native host unavailable" }, {}]) {
        const env = await popupEnvironment({ getStatus: { native: false }, openDesktop: response });
        const button = env.elements.openDesktopBtn;
        assert.equal(button.disabled, false);
        const opening = button.dispatch("click");
        assert.equal(button.disabled, true);
        await opening;
        assert.equal(button.disabled, false);
        assert.equal(env.messages.at(-1).action, "openDesktop");
        assert.equal(env.elements.output.innerText, response.success
            ? "Desktop app launch requested." : response.error || "Could not open the desktop app");
    }
});

test("credential prompt can stop offering to save on this site", async () => {
    const env = await credentialPromptEnvironment();
    env.elements.never.dispatch("click", { isTrusted: false });
    await settle();
    assert.equal(env.messages.some(message => message.selection?.action === "never"), false);
    env.elements.never.dispatch("click", { isTrusted: true });
    await settle();
    assert.equal(env.messages.at(-1).selection.action, "never");
    assert.equal(env.context.closed, true);
});

test("picker supports search, arrow keys, Enter, and Escape", async () => {
    const env = await pickerEnvironment([
        { id: 1, name: "Work", username: "w@corp" },
        { id: 2, name: "GitHub", username: "me" },
        { id: 3, name: "GitLab", username: "GitLab" },
    ]);
    const key = (name, target = env.elements.search, isTrusted = true, repeat = false) =>
        env.documentListeners.get("keydown")({ key: name, target, isTrusted, repeat, preventDefault() {} });
    assert.equal(env.elements.search.focused, true);
    key("Enter");
    await settle();
    assert.equal(env.messages.at(-1).action, "getSecurePickerData", "Enter without a highlight fills nothing");
    env.elements.search.value = "w";
    env.elements.search.dispatch("input");
    key("Enter");
    await settle();
    assert.equal(env.messages.at(-1).action, "getSecurePickerData", "Enter right after opening fills nothing");
    env.advance();
    key("Enter", env.elements.search, true, true);
    await settle();
    assert.equal(env.messages.at(-1).action, "getSecurePickerData", "a held Enter key fills nothing");
    env.elements.search.value = "";
    env.elements.search.dispatch("input");
    assert.equal(env.elements.items.children.length, 3);
    assert.equal(env.elements.items.children[0].children[0].textContent, "W");
    env.elements.search.value = "git";
    env.elements.search.dispatch("input");
    assert.equal(env.elements.items.children.length, 2);
    assert.equal(env.elements.items.children[0].className, "active");
    assert.equal(env.elements.items.children[1].children[1].children.length, 1, "duplicate username hidden");
    key("ArrowDown", env.elements.search, false);
    assert.equal(env.elements.items.children[0].className, "active", "synthetic keys ignored");
    key("ArrowDown");
    assert.equal(env.elements.items.children[1].className, "active");
    key("Home");
    assert.equal(env.elements.items.children[1].className, "active", "Home edits the search text");
    key("ArrowUp", env.elements.items.children[1]);
    assert.equal(env.elements.items.children[0].focused, true);
    env.elements.items.children[1].dispatch("focus");
    key("Enter");
    await settle();
    assert.equal(env.messages.at(-1).id, 3);
    env.elements.search.value = "zzz";
    env.elements.search.dispatch("input");
    assert.match(env.elements.status.textContent, /No accounts match/);
    key("Enter");
    key("Escape");
    await settle();
    assert.equal(env.messages.at(-1).cancel, true);
});

test("popup generator persists settings and copies the visible password", async () => {
    const env = await popupEnvironment({
        getStatus: { native: true, running: true, locked: false },
        storage: { pmGenerator: { length: 30 }, pmNeverSave: ["https://a.test", "https://b.test"] }
    });
    assert.equal(env.elements.genValue.textContent.length, 30);
    assert.equal(env.elements.genLengthValue.textContent, "30");
    env.elements.genLength.value = "16";
    env.elements.genLength.dispatch("input", { target: env.elements.genLength });
    assert.equal(env.elements.genValue.textContent.length, 16);
    assert.equal(env.stored.pmGenerator.length, 16);
    env.elements.genSymbols.dispatch("change", { target: { checked: false } });
    assert.match(env.elements.genValue.textContent, /^[A-Za-z0-9]+$/);
    env.elements.genPassphrase.dispatch("change", { target: { checked: true } });
    env.elements.genPassphrase.checked = true;
    assert.equal(env.stored.pmGenerator.mode, "passphrase");
    assert.equal(env.elements.genSymbols.disabled, true);
    env.elements.genLength.value = "4";
    env.elements.genLength.dispatch("input", { target: env.elements.genLength });
    assert.equal(env.elements.genValue.textContent.split("-").length, 4);
    const before = env.elements.genValue.textContent;
    env.elements.genNew.dispatch("click");
    assert.notEqual(env.elements.genValue.textContent, before);
    await env.elements.genCopy.dispatch("click");
    assert.equal(env.context.copied, env.elements.genValue.textContent);
    assert.match(env.elements.output.innerText, /copied/);
    assert.equal(env.elements.neverSave.hidden, false);
    assert.equal(env.elements.neverCount.textContent, "2");
    const allow = env.elements.neverList.children[0].children[1];
    allow.dispatch("click");
    assert.deepEqual(env.stored.pmNeverSave, ["https://b.test"]);
    assert.equal(env.elements.neverCount.textContent, "1");
});

test("popup generator falls back to defaults and reports clipboard failures", async () => {
    const env = await popupEnvironment({
        getStatus: { native: true },
        clipboardFails: true,
        storage: { pmGenerator: { symbolSet: "", uppercase: false, lowercase: false, digits: false } }
    });
    assert.equal(env.elements.genValue.textContent.length, 20);
    await env.elements.genCopy.dispatch("click");
    assert.match(env.elements.output.innerText, /Could not copy/);
    assert.equal(env.elements.neverSave.hidden, true);
    const fresh = await popupEnvironment({ getStatus: { native: true }, storage: { pmGenerator: "x" } });
    assert.equal(fresh.elements.genValue.textContent.length, 20);
    fresh.elements.genValue.textContent = "";
    await fresh.elements.genCopy.dispatch("click");
    assert.equal(fresh.context.copied, undefined);
});
