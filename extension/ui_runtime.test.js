const test = require("node:test");
const assert = require("node:assert/strict");
const { loadModule } = require("./test_harness.cjs");

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
    querySelector(selector) {
        for (const child of this.children) {
            if (child.tagName === selector.toUpperCase()) return child;
            const found = child.querySelector?.(selector);
            if (found) return found;
        }
        return null;
    }
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
        createElement(tag = "") {
            const element = new FakeElement();
            element.tagName = String(tag).toUpperCase();
            return element;
        },
        addEventListener(type, listener) { documentListeners.set(type, listener); }
    };
    let runtimeListener;
    const context = {
        document,
        location: { search },
        URL,
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

// The worker lease is exercised by its own tests; pages here run without it.
function execute(name, context) {
    return loadModule(name, context, { "./ui_session.js": {} });
}

const settle = () => new Promise(resolve => setImmediate(resolve));

async function popupEnvironment(responses) {
    const env = environment([
        "statusDot", "statusText", "lockBtn", "openDesktopBtn", "output", "nativeHint", "recovery", "operation",
        "reviewOperation", "unknownReview", "inspected", "acknowledgeOperation", "genValue", "genNew", "genCopy",
        "genLength", "genLengthValue", "genSymbols", "genPassphrase", "neverSave", "neverCount",
        "neverList", "setupCard", "setupCommand", "copySetupCommand", "extensionId", "copyExtensionId",
        "retryBtn", "siteSection", "siteTitle", "siteSearch", "siteList", "siteEmpty", "addLoginBtn",
        "addForm", "addName", "addUsername", "addPassword", "addRegenerate", "addSave", "addCancel",
        "genUppercase", "genDigits", "genAmbiguous", "genSeparator", "shortcuts",
        "vaultSearch", "vaultQuery", "vaultResults", "vaultEmpty", "reconnectBtn"
    ], responses);
    env.page = execute("popup.js", env.context);
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
    assert.equal(env.elements.statusText.innerText, "Unlocked");
    assert.equal(env.elements.statusDot.className, "dot success");
    assert.equal(env.elements.lockBtn.disabled, false);
    await env.elements.lockBtn.dispatch("click");
    assert.equal(env.elements.output.innerText, "Vault locked.");
    env.runtimeListener()({ action: "statusChanged", status: { native: true } });
    assert.equal(env.elements.statusText.innerText, "Service stopped");
    assert.match(env.elements.nativeHint.textContent, /desktop app/);
    assert.equal(env.elements.siteSection.hidden, true);
    env.runtimeListener()({ action: "statusChanged", status: { native: false } });
    assert.match(env.elements.nativeHint.textContent, /Connect this browser/);
    assert.equal(env.elements.setupCard.hidden, false);
    env.runtimeListener()({ action: "statusChanged", status: { native: true, running: true, locked: true } });
    assert.match(env.elements.nativeHint.textContent, /Unlock/);
    assert.equal(env.elements.setupCard.hidden, true);
    env.runtimeListener()({ action: "statusChanged", status: { native: true, running: true, locked: false } });
    assert.equal(env.elements.nativeHint.hidden, true);
    assert.equal(env.elements.siteSection.hidden, false);
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
        "credentials", "site", "status", "name", "username", "usernameLabel", "updateNote", "reviewOutcome", "add", "update", "cancel", "never",
        "passwordMask", "password", "revealPassword", "chooseOther", "chooser", "targetSearch", "targetResults"
    ], responses, "?token=prompt-token");
    env.elements.password.hidden = true; // as in credential_prompt.html
    env.elements.chooser.hidden = true;
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

test("credential prompt reveals and corrects the captured password, and Escape means not now", async () => {
    const env = await credentialPromptEnvironment({
        revealCredentialPassword: { success: true, password: "captured-secret" },
    });
    env.messages.length = 0;
    await env.elements.revealPassword.dispatch("click", { isTrusted: false });
    assert.equal(env.messages.length, 0, "untrusted clicks reveal nothing");
    await env.elements.revealPassword.dispatch("click", { isTrusted: true });
    assert.equal(env.elements.password.value, "captured-secret");
    assert.equal(env.elements.password.hidden, false);
    assert.equal(env.elements.revealPassword.textContent, "Hide");
    await env.elements.revealPassword.dispatch("click", { isTrusted: true });
    assert.equal(env.elements.password.hidden, true);
    env.elements.update.dispatch("click", { isTrusted: true });
    await settle();
    assert.equal(env.messages.at(-1).selection.password, undefined, "an unedited password is not resent");

    const edited = await credentialPromptEnvironment({
        revealCredentialPassword: { success: true, password: "captured-secret" },
    });
    await edited.elements.revealPassword.dispatch("click", { isTrusted: true });
    edited.elements.password.value = "corrected-secret";
    edited.elements.password.dispatch("input");
    assert.match(edited.elements.passwordMask.textContent, /16 characters/);
    edited.elements.add.dispatch("click", { isTrusted: true });
    edited.elements.credentials.dispatch("submit", { isTrusted: true });
    await settle();
    assert.equal(edited.messages.at(-1).selection.password, "corrected-secret");

    const escaping = await credentialPromptEnvironment();
    escaping.documentListeners.get("keydown")({ key: "Escape", isTrusted: true, repeat: false });
    await settle();
    assert.equal(escaping.messages.at(-1).selection.action, "cancel");

    const expired = await credentialPromptEnvironment({ revealCredentialPassword: { success: false } });
    await expired.elements.revealPassword.dispatch("click", { isTrusted: true });
    assert.match(expired.elements.status.textContent, /unavailable/);
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

test("the popup has no master-password field and unlocks only through the desktop app", async () => {
    const env = await popupEnvironment({ getStatus: { native: true, running: true, locked: true } });
    assert.equal(env.elements.openDesktopBtn.textContent, "Unlock in desktop app");
    assert.match(env.elements.nativeHint.textContent, /desktop app/);
    assert.equal(env.messages.some(message => ["unlockVault", "listVaults"].includes(message.action)), false);
    const html = require("node:fs").readFileSync(require("node:path").join(__dirname, "popup.html"), "utf8");
    // The only password input is for a login being added, never the master password.
    const inputs = [...html.matchAll(/<input[^>]*type="password"[^>]*>/g)].map(match => match[0]);
    assert.equal(inputs.length, 1);
    assert.match(inputs[0], /id="addOwnPassword"/);
    assert.doesNotMatch(html, /master password/i);
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
    // Connected: the desktop service copies; a refusal is shown, never bypassed.
    await env.elements.genCopy.dispatch("click");
    assert.equal(env.context.copied, undefined);
    assert.match(env.elements.output.innerText, /Could not/);
    assert.equal(env.messages.at(-1).action, "popupCopyGenerated");
    assert.equal(env.elements.neverSave.hidden, false);
    assert.equal(env.elements.neverCount.textContent, "2");
    const allow = env.elements.neverList.children[0].children[1];
    allow.dispatch("click");
    assert.deepEqual(env.stored.pmNeverSave, ["https://b.test"]);
    assert.equal(env.elements.neverCount.textContent, "1");
});

test("popup lists this site's logins and fills, copies, and adds through the worker", async () => {
    const items = [
        { id: 4, name: "Work", username: "w@corp", hasTotp: true },
        { id: 5, name: "Spare", username: "", hasTotp: false },
    ];
    const responses = {
        getStatus: { native: true, running: true, locked: false },
        popupLogins: { success: true, site: "https://example.com", items },
        popupCopy: { success: true, data: "Password copied. The clipboard clears in 30 seconds." },
        popupFill: { success: false, error: "No sign-in form was found on this page." },
        popupSave: { success: true, data: "Saved" },
        popupCopyGenerated: { success: true, data: "Password copied. The clipboard clears in 30 seconds." },
    };
    const env = await popupEnvironment(responses);
    await settle();
    assert.equal(env.elements.siteTitle.textContent, "Logins for example.com");
    assert.equal(env.elements.siteList.children.length, 2);
    assert.equal(env.elements.siteSearch.hidden, true, "search appears only for longer lists");
    const [work, spare] = env.elements.siteList.children;
    const workButtons = work.children[1].children;
    assert.deepEqual(workButtons.map(button => button.textContent), ["Fill", "Copy username", "Copy password", "Copy code"]);
    assert.deepEqual(spare.children[1].children.map(button => button.textContent), ["Fill", "Copy password"]);
    await workButtons[2].dispatch("click");
    assert.equal(JSON.stringify(env.messages.at(-1)), JSON.stringify({ action: "popupCopy", id: 4, field: "password" }));
    assert.match(env.elements.output.innerText, /clears in 30 seconds/);
    await workButtons[3].dispatch("click");
    assert.equal(env.messages.at(-1).field, "totp");
    await workButtons[0].dispatch("click");
    assert.equal(env.messages.at(-1).action, "popupFill");
    assert.equal(env.elements.output.className, "error");
    responses.popupFill = { success: true };
    await workButtons[0].dispatch("click");
    assert.equal(env.context.closed, true, "a successful fill closes the popup");

    // Adding a login uses a generated password and never a typed one.
    env.elements.addForm.hidden = true; // as in popup.html
    await env.elements.addLoginBtn.dispatch("click");
    assert.equal(env.elements.addForm.hidden, false);
    assert.equal(env.elements.addName.value, "example.com");
    assert.ok(env.elements.addPassword.textContent.length >= 8);
    env.elements.addName.value = "";
    await env.elements.addForm.dispatch("submit");
    assert.match(env.elements.output.innerText, /Enter a name/);
    env.elements.addName.value = "New account";
    env.elements.addUsername.value = "me";
    const generated = env.elements.addPassword.textContent;
    await env.elements.addForm.dispatch("submit");
    const save = env.messages.find(message => message.action === "popupSave");
    assert.equal(save.name, "New account");
    assert.equal(save.password, generated);
    assert.equal(env.elements.addForm.hidden, true);
    assert.equal(env.elements.addPassword.textContent, "", "a closed form keeps no generated password");

    // Generated passwords are copied by the desktop service when it is connected.
    await env.elements.genCopy.dispatch("click");
    assert.equal(env.context.copied, undefined);
    assert.match(env.elements.output.innerText, /clears in 30 seconds/);

    responses.popupLogins = { success: true, site: "https://example.com", items: [...items, ...items] };
    env.runtimeListener()({ action: "statusChanged", status: { native: true, running: true, locked: true } });
    env.runtimeListener()({ action: "statusChanged", status: { native: true, running: true, locked: false } });
    await settle();
    assert.equal(env.elements.siteSearch.hidden, false);
    env.elements.siteSearch.value = "zzz";
    env.elements.siteSearch.dispatch("input");
    assert.match(env.elements.siteEmpty.textContent, /No logins match/);
});

test("popup searches the whole vault and copies results through the desktop service", async () => {
    const responses = {
        getStatus: { native: true, running: true, locked: false },
        popupLogins: { success: true, site: "https://example.com", items: [] },
        popupSearch: { success: true, total: 3, items: [
            { id: 9, name: "Bank", username: "me", kind: "login", site: "https://bank.example" },
            { id: 10, name: "Wi-Fi", username: "", kind: "wifi", site: "" },
        ] },
        popupCopyItem: { success: true, data: "Password copied. The clipboard clears in 15 seconds." },
    };
    const env = await popupEnvironment(responses);
    await settle();
    assert.equal(env.elements.vaultSearch.hidden, false);
    env.elements.vaultQuery.value = "b";
    await env.page.searchVault();
    assert.equal(env.messages.some(message => message.action === "popupSearch"), false, "one letter does not search");
    env.elements.vaultQuery.value = "ba";
    await env.page.searchVault();
    assert.equal(env.elements.vaultResults.children.length, 2);
    assert.match(env.elements.vaultEmpty.textContent, /Showing 2 of 3/);
    const bankButtons = env.elements.vaultResults.children[0].children[1].children;
    assert.deepEqual(bankButtons.map(button => button.textContent), ["Copy username", "Copy password", "Open"]);
    // "Open" hands the item to the desktop app for viewing and editing.
    await bankButtons[2].dispatch("click");
    assert.equal(env.messages.at(-1).action, "openDesktop");
    assert.equal(env.messages.at(-1).id, 9);
    await bankButtons[1].dispatch("click");
    assert.equal(env.messages.at(-1).action, "popupCopyItem");
    assert.equal(env.messages.at(-1).id, 9);
    assert.match(env.elements.output.innerText, /clears in 15/);
    await bankButtons[0].dispatch("click");
    assert.equal(env.context.copied, undefined, "usernames are copied by the desktop app too");
    assert.equal(env.messages.at(-1).field, "username");
    // Typed items use their own labels from the shared item profiles.
    assert.equal(env.elements.vaultResults.children[1].children[1].children[0].textContent, "Copy Wi-Fi password");
    responses.popupSearch = { success: true, total: 0, items: [] };
    await env.page.searchVault();
    assert.match(env.elements.vaultEmpty.textContent, /No items match/);
    responses.popupSearch = { success: false, error: "Search failed hard" };
    await env.page.searchVault();
    assert.match(env.elements.vaultEmpty.textContent, /Search failed hard/);
});

test("popup handles lost connections, uncertain saves, and offline copying explicitly", async () => {
    const responses = {
        getStatus: { native: true, running: true, locked: false },
        popupLogins: { success: true, site: "https://example.com", items: [] },
        popupSave: { success: false, uncertain: true, error: "timed out" },
    };
    const env = await popupEnvironment(responses);
    await settle();
    env.elements.addForm.hidden = true;
    await env.elements.addLoginBtn.dispatch("click");
    env.elements.addName.value = "New";
    await env.elements.addForm.dispatch("submit");
    assert.match(env.elements.output.innerText, /may have completed/);
    assert.equal(env.elements.addForm.hidden, true, "the form closes so the save is not repeated");

    // A failed status check turns actions off instead of trusting the cached state.
    responses.getStatus = { success: false, error: "worker gone" };
    await env.page.refreshStatus();
    assert.equal(env.elements.statusText.innerText, "Reconnecting…");
    assert.equal(env.elements.siteSection.hidden, true);
    assert.equal(env.elements.vaultSearch.hidden, true);

    // With no desktop service, copying a generated password needs a second click.
    await env.elements.genCopy.dispatch("click");
    assert.equal(env.context.copied, undefined);
    assert.match(env.elements.output.innerText, /again to copy anyway/);
    await env.elements.genCopy.dispatch("click");
    assert.equal(env.context.copied, env.elements.genValue.textContent);
});

test("popup clears an unsaved login on lock, marks stale searches, and reconnects", async () => {
    const responses = {
        getStatus: { native: true, running: true, locked: false },
        popupLogins: { success: true, site: "https://example.com", items: [] },
        popupSearch: { success: true, total: 1, items: [{ id: 1, name: "Bank", username: "me", kind: "login", site: "" }] },
    };
    const env = await popupEnvironment(responses);
    await settle();
    // Closing the form returns focus to the button that opened it.
    await env.elements.addLoginBtn.dispatch("click");
    await env.elements.addCancel.dispatch("click");
    assert.equal(env.elements.addLoginBtn.focused, true);
    // A draft left open is erased, with a notice, when the vault locks.
    await env.elements.addLoginBtn.dispatch("click");
    env.elements.addUsername.value = "me";
    env.runtimeListener()({ action: "statusChanged", status: { native: true, running: true, locked: true } });
    assert.equal(env.elements.addForm.hidden, true);
    assert.equal(env.elements.addUsername.value, "");
    assert.match(env.elements.output.innerText, /cleared because the vault locked/);
    // Unlocking again: typing marks earlier results stale until the new search answers.
    env.runtimeListener()({ action: "statusChanged", status: { native: true, running: true, locked: false } });
    env.elements.vaultQuery.value = "ba";
    await env.page.searchVault();
    assert.equal(env.elements.vaultResults.children.length, 1);
    env.elements.vaultQuery.value = "ban";
    await env.elements.vaultQuery.dispatch("input");
    assert.equal(env.elements.vaultResults.children.length, 0);
    assert.match(env.elements.vaultEmpty.textContent, /Searching/);
    env.elements.vaultQuery.value = "b";
    await env.elements.vaultQuery.dispatch("input");
    assert.equal(env.elements.vaultEmpty.hidden, true);

    // A lost worker connection offers Reconnect, which recovers once status answers.
    const broken = await popupEnvironment({ getStatus: { success: false, error: "worker gone" } });
    assert.equal(broken.elements.reconnectBtn.hidden, false);
    broken.context.document.visibilityState = "visible";
    Object.assign(broken.context.chrome.runtime, {
        sendMessage(message, callback) {
            broken.messages.push(message);
            callback({ native: true, running: true, locked: true });
        },
    });
    await broken.elements.reconnectBtn.dispatch("click");
    await settle();
    assert.equal(broken.elements.reconnectBtn.hidden, true);
    assert.match(broken.elements.output.innerText, /Reconnected/);
});

test("popup explains insecure pages and guides setup when disconnected", async () => {
    const env = await popupEnvironment({
        getStatus: { native: true, running: true, locked: false },
        popupLogins: { success: true, site: null, reason: "insecure", host: "http://router.local", items: [] },
    });
    await settle();
    assert.match(env.elements.siteEmpty.textContent, /not encrypted/);
    assert.equal(env.elements.addLoginBtn.hidden, true);

    const setup = await popupEnvironment({ getStatus: { native: false } });
    assert.match(setup.elements.setupCommand.textContent, /pm native-host install --browser/);
    await setup.elements.copySetupCommand.dispatch("click");
    assert.equal(setup.context.copied, setup.elements.setupCommand.textContent);
    await setup.elements.retryBtn.dispatch("click");
    assert.match(setup.elements.output.innerText, /Still not connected/);

    const broken = await popupEnvironment({ getStatus: { success: false, error: "worker gone" } });
    assert.match(broken.elements.nativeHint.textContent, /reconnecting automatically/);
});

test("popup generator falls back to defaults and reports clipboard failures", async () => {
    const env = await popupEnvironment({
        getStatus: { native: true },
        clipboardFails: true,
        storage: { pmGenerator: { symbolSet: "", uppercase: false, lowercase: false, digits: false } }
    });
    assert.equal(env.elements.genValue.textContent.length, 20);
    await env.elements.genCopy.dispatch("click");
    assert.match(env.elements.output.innerText, /copy anyway/);
    await env.elements.genCopy.dispatch("click");
    assert.match(env.elements.output.innerText, /Could not copy/);
    assert.equal(env.elements.neverSave.hidden, true);
    const fresh = await popupEnvironment({ getStatus: { native: true }, storage: { pmGenerator: "x" } });
    assert.equal(fresh.elements.genValue.textContent.length, 20);
    fresh.elements.genValue.textContent = "";
    await fresh.elements.genCopy.dispatch("click");
    assert.equal(fresh.context.copied, undefined);
});

test("passkey prompt shows the browser-reported site and sends only explicit choices", async () => {
    const ids = ["title", "destination", "status", "choices", "confirm", "fallback", "cancel", "verify", "verifyHint", "confirmInDesktop", "openDesktop"];
    const prompt = async (data, completion = { success: true }, query = "?token=t1") => {
        const env = environment(ids, { getPasskeyPromptData: data, completePasskeyPrompt: completion }, query);
        env.elements.verify.hidden = true;
        execute("passkey_prompt.js", env.context);
        await settle();
        return env;
    };
    const site = { success: true, origin: "https://login.example.com", rp: "example.com", locked: false, canConfirm: true };
    for (const [data, expectedTitle] of [
        [{ ...site, kind: "get", user: "", choices: [{ id: 3, userName: "alice", displayName: "Alice" }, { id: 4, userName: "bob", displayName: "bob" }] },
            "Sign in with a passkey"],
        [{ ...site, kind: "create", user: "alice", choices: [] }, "Save a passkey"],
    ]) {
        const env = await prompt(data);
        assert.equal(env.elements.title.textContent, expectedTitle);
        assert.match(env.elements.destination.textContent, /login\.example\.com/);
        assert.equal(env.elements.confirm.disabled, false);
        if (data.kind === "get") {
            assert.equal(env.elements.choices.children.length, 2);
            const [, second] = env.elements.choices.children;
            second.children[0].dispatch("change");
            assert.equal(second.children[1].textContent, "bob");
            assert.equal(env.elements.choices.children[0].children[1].textContent, "Alice (alice)");
        }
        env.elements.confirm.dispatch("click", { isTrusted: false });
        await settle();
        assert.equal(env.messages.some(message => message.action === "completePasskeyPrompt"), false);
        // Optional proof by default; nothing is ever typed into this window.
        assert.equal(env.elements.verify.hidden, false);
        assert.equal(env.elements.confirmInDesktop.checked, false);
        assert.match(env.elements.verifyHint.textContent, /Optional/);
        env.elements.confirmInDesktop.checked = data.kind === "get";
        env.elements.confirm.dispatch("click", { isTrusted: true });
        await settle();
        const completion = env.messages.find(message => message.action === "completePasskeyPrompt");
        assert.equal(completion.selection.confirmInDesktop, data.kind === "get" ? true : undefined);
        assert.equal("password" in completion.selection, false);
        assert.equal(completion.token, "t1");
        assert.equal(completion.selection.action, "confirm");
        if (data.kind === "get") assert.equal(completion.selection.id, 4);
        assert.equal(env.context.closed, true);
    }

    const locked = await prompt({ ...site, kind: "create", origin: "not a url", user: "a", locked: true, choices: [] },
        { success: false, error: "Passkey request expired" }, "?token=t2");
    assert.match(locked.elements.status.textContent, /locked/);
    assert.equal(locked.elements.confirm.disabled, true);
    locked.elements.fallback.dispatch("click");
    await settle();
    assert.equal(locked.messages.at(-1).selection.action, "fallback");
    assert.equal(locked.elements.status.textContent, "Passkey request expired");
    assert.equal(locked.elements.cancel.disabled, false);
    locked.elements.cancel.dispatch("click");
    await settle();
    assert.equal(locked.messages.at(-1).selection.action, "cancel");

    // Required proof: the box is checked and fixed; a refusal can be retried.
    const required = await prompt({ ...site, kind: "create", user: "a", verification: "required", choices: [] },
        { success: false, error: "Refused in the desktop app." }, "?token=t4");
    assert.equal(required.elements.confirmInDesktop.checked, true);
    assert.equal(required.elements.confirmInDesktop.disabled, true);
    assert.match(required.elements.verifyHint.textContent, /requires/);
    required.elements.confirm.dispatch("click", { isTrusted: true });
    assert.match(required.elements.status.textContent, /desktop app/);
    assert.equal(required.elements.cancel.disabled, false, "cancel stays available while waiting");
    await settle();
    assert.equal(required.elements.status.textContent, "Refused in the desktop app.");
    assert.equal(required.elements.confirm.disabled, false, "the person can try again");

    const discouraged = await prompt({ ...site, kind: "create", user: "a", verification: "discouraged", choices: [] }, undefined, "?token=t5");
    assert.equal(discouraged.elements.verify.hidden, true);

    // A vault with no master password or PIN: no proof offered; required sites are explained.
    const plain = await prompt({ ...site, kind: "create", user: "a", canConfirm: false, choices: [] }, undefined, "?token=t6");
    assert.equal(plain.elements.verify.hidden, true);
    assert.equal(plain.elements.confirm.disabled, false, "presence-only registration still works");
    const strict = await prompt({ ...site, kind: "create", user: "a", canConfirm: false, verification: "required", choices: [] }, undefined, "?token=t7");
    assert.equal(strict.elements.verify.hidden, true);
    assert.match(strict.elements.status.textContent, /passkey PIN.*another passkey provider/);
    assert.equal(strict.elements.confirm.disabled, true);

    const expired = environment(ids, { getPasskeyPromptData: { success: false, error: "Passkey request expired" } }, "?token=t3");
    execute("passkey_prompt.js", expired.context);
    await settle();
    assert.equal(expired.elements.status.textContent, "Passkey request expired");
});

test("credential prompt can update a login saved for another site, adding this site", async () => {
    const env = await credentialPromptEnvironment({
        getCredentialPromptData: { success: true, data: {
            site: "https://login.example.com", message: "Would you like to save these credentials?",
            suggestedName: "login.example.com", username: "alice", askForUsername: false, hasAccounts: false,
            updateTarget: null
        } },
        searchCredentialTargets: { success: true, items: [
            { id: 7, name: "Example", username: "alice", site: "https://www.example.com" }
        ] },
        chooseCredentialTarget: { success: true, data: {
            site: "https://login.example.com", message: "Update the saved password for “Example”.",
            suggestedName: "login.example.com", username: "alice", askForUsername: false, hasAccounts: true,
            preferUpdate: true, updateTarget: { id: 7, name: "Example", username: "alice", addSite: true },
            updateNote: "This site's address will be added to “Example”."
        } }
    });
    assert.equal(env.elements.update.hidden, true, "no saved login matches this site yet");
    env.elements.chooseOther.dispatch("click", { isTrusted: true });
    assert.equal(env.elements.chooser.hidden, false);

    // Enter in the search box must never submit the save-as-new form.
    let prevented = false;
    env.elements.targetSearch.dispatch("keydown", { key: "Enter", preventDefault() { prevented = true; } });
    assert.equal(prevented, true);
    assert.equal(env.messages.some(message => message.action === "completeCredentialPrompt"), false);

    env.elements.targetSearch.value = "exam";
    env.elements.targetSearch.dispatch("input");
    await new Promise(resolve => setTimeout(resolve, 250));
    await settle();
    const search = env.messages.find(message => message.action === "searchCredentialTargets");
    assert.deepEqual({ token: search.token, query: search.query }, { token: "prompt-token", query: "exam" });
    const result = env.elements.targetResults.children[0].children[0];
    assert.match(result.children[1].textContent, /alice · https:\/\/www.example.com/);

    result.dispatch("click", { isTrusted: false });
    await settle();
    assert.equal(env.messages.some(message => message.action === "chooseCredentialTarget"), false);
    result.dispatch("click", { isTrusted: true });
    await settle();
    assert.equal(env.messages.at(-1).action, "chooseCredentialTarget");
    assert.equal(env.messages.at(-1).entryId, 7);
    assert.equal(env.elements.update.hidden, false);
    assert.equal(env.elements.update.className, "primary");
    assert.equal(env.elements.update.textContent, "Update “Example”");
    assert.match(env.elements.updateNote.textContent, /address will be added/);
    assert.equal(env.elements.chooser.hidden, true);

    env.elements.update.dispatch("click", { isTrusted: true });
    await settle();
    assert.equal(env.messages.at(-1).selection.action, "update");
});
