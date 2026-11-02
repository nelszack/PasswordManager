const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

class Element {
    constructor(tag = "div") { this.tag = tag; this.children = []; this.listeners = {}; this.value = ""; this.hidden = false; this.disabled = false; this.checked = false; this.textContent = ""; this.isConnected = true; }
    addEventListener(type, handler) { this.listeners[type] = handler; }
    append(...children) { this.children.push(...children); for (const child of children) child.parentElement = this; }
    replaceWith(replacement) { const siblings = this.parentElement.children; siblings[siblings.indexOf(this)] = replacement; replacement.parentElement = this.parentElement; this.isConnected = false; }
    replaceChildren(...children) { for (const child of this.children) child.isConnected = false; this.children = children; }
    querySelectorAll(selectors) { return this.children.flatMap(child => [ ...(selectors.split(",").includes(child.tag) ? [child] : []), ...child.querySelectorAll(selectors) ]); }
    setAttribute(name, value) { (this.attributes ||= {})[name] = String(value); }
    getAttribute(name) { return this.attributes?.[name] ?? null; }
    focus() { this.focused = true; }
    reset() {}
    click(trusted = true) { this.listeners.click?.({ preventDefault() {}, isTrusted: trusted }); }
    get tagName() { return this.tag.toUpperCase(); }
    get type() { return this.tag === "textarea" ? "textarea" : this._type; }
    set type(value) { if (this.tag === "textarea") throw new TypeError("Textarea type is read-only"); this._type = value; }
    get value() { return this._value || ""; }
    set value(value) { this._value = this.tag === "input" ? String(value).replace(/[\r\n]/g, "") : this.tag === "textarea" ? String(value).replace(/\r\n?/g, "\n") : String(value); }
}
function environment() {
    const html = fs.readFileSync(path.join(__dirname, "manager.html"), "utf8");
    const elements = Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(match => [match[1], new Element()]));
    elements.password.parentElement = new Element();
    elements.password.tag = "input"; elements.secretMultiline.tag = "textarea";
    elements.name.tag = "input"; elements.username.tag = "input"; elements.notes.tag = "textarea";
    elements.multilineLabel.hidden = true;
    elements.editForm.reset = () => { elements.password.value = ""; elements.secretMultiline.value = ""; elements.kind.value = "login"; };
    const calls = [], timers = new Map(), responses = new Map(), windowEvents = new Map(); let timerId = 0, confirmations = 0, listener, confirmResult = true;
    let pending = [{ id: "test-request", application: "Example VPN", username: "alice", location: "Example City", summary: "Login", expires_at: Math.floor(Date.now()/1000)+300, code_digits: 3, unsupported: null, fingerprint: "a".repeat(128) }];
    const context = vm.createContext({ module: { exports: {} }, require: name => name === "./password_generator.js" ? { defaults: {}, validate: () => ({}) } : require(name), document: { getElementById: id => elements[id], createElement: tag => new Element(tag), createTextNode: () => new Element() },
        window: { addEventListener: (name, handler) => windowEvents.set(name, handler), confirm: () => { confirmations++; return confirmResult; } },
        setTimeout: callback => { timers.set(++timerId, callback); return timerId; }, clearTimeout: id => timers.delete(id),
        PasswordManagerGenerator: { defaults: {}, validate: () => ({}) },
        chrome: { runtime: { onMessage: { addListener: handler => { listener = handler; } }, sendMessage: (request, callback) => {
            calls.push(request);
            if (responses.has(request.action)) { const response = responses.get(request.action); if (typeof response === "function") response(request, callback); else callback(response); return; }
            if (request.action === "getStatus") { callback({ native: true, running: true, locked: false, sessionId: "a".repeat(64) }); return; }
            let data;
            if (request.action === "managerVaults") data = [];
            if (request.action === "managerList") data = { total: 0, items: [] };
            if (request.action === "managerItem") data = { id: 1, name: "work", kind: "login", fields: [], urls: [], has_duo: true };
            if (request.action === "managerDuoRequests") data = pending;
            if (request.action === "managerDuoRespond") { data = request.approve ? "approved" : "denied"; pending = []; }
            callback({ success: true, data });
        } }, storage: { local: { get: (_key, callback) => callback?.({}) } } }
    });
    vm.runInContext(fs.readFileSync(path.join(__dirname, "manager.js"), "utf8"), context);
    context.api = context.module.exports.create();
    return { context, elements, calls, timers, windowEvents, publishStatus: status => listener({ action: "statusChanged", status }), setResponse: (action, value) => value === undefined ? responses.delete(action) : responses.set(action, value), setPending: value => { pending = value; }, lock: () => listener({ action: "statusChanged", status: { native: true, running: true, locked: true } }), setConfirm: value => { confirmResult = value; }, confirmations: () => confirmations };
}
const flush = () => new Promise(resolve => setImmediate(resolve));

test("changing item types preserves the edited secret and keeps only the visible control populated", async () => {
    const env = environment(); await flush(); await vm.runInContext("api.openItem(1);", env.context);
    env.elements.password.value = "  edited secret  ";
    env.elements.kind.value = "secure-note"; env.elements.kind.listeners.change();
    assert.equal(env.elements.secretMultiline.value, "  edited secret  ");
    assert.equal(env.elements.password.value, "");
    env.elements.kind.value = "login"; env.elements.kind.listeners.change();
    assert.equal(env.elements.password.value, "  edited secret  ");
    assert.equal(env.elements.secretMultiline.value, "");
    env.elements.kind.value = "ssh-key"; env.elements.kind.listeners.change();
    env.elements.secretMultiline.value = "first line\nsecond line";
    env.elements.kind.value = "api-secret"; env.elements.kind.listeners.change();
    assert.equal(env.elements.multilineLabel.hidden, false);
    assert.equal(vm.runInContext("api.secretControl().value", env.context), "first line\nsecond line");
    env.elements.cancel.click();
    assert.equal(env.elements.password.value, "");
    assert.equal(env.elements.secretMultiline.value, "");
});

test("revealed secrets retain their expiry when moved between editor controls", async () => {
    const env = environment(); await flush(); await vm.runInContext("api.openItem(1);", env.context);
    env.setResponse("managerItem", { success: true, data: { password: "synthetic-secret", fields: [] } });
    env.elements.reveal.click(); await flush();
    env.elements.kind.value = "secure-note"; env.elements.kind.listeners.change();
    assert.equal(env.elements.secretMultiline.value, "synthetic-secret");
    for (const expire of env.timers.values()) expire();
    assert.equal(env.elements.secretMultiline.value, "");
    assert.equal(env.elements.password.value, "");
});

test("revealing a multiline secret uses a textarea even for a single-line item type", async () => {
    const env = environment(); await flush(); await vm.runInContext("api.openItem(1);", env.context);
    env.setResponse("managerItem", { success: true, data: { password: "line one\nline two", fields: [] } });
    env.elements.reveal.click(); await flush();
    assert.equal(env.elements.secretMultiline.value, "line one\nline two");
    assert.equal(env.elements.multilineLabel.hidden, false);
    for (const expire of env.timers.values()) expire();
    assert.equal(env.elements.secretMultiline.value, "");
});

test("manager preserves multiline custom fields and revealed primary bytes on unrelated saves", async () => {
    const env = environment(); await flush();
    const plain = "public first\r\npublic second\rlast";
    const secret = "private first\r\nprivate second\rlast";
    env.setResponse("managerItem", { success: true, data: { id: 1, name: "work", kind: "login", notes: "notes\r\nsecond line", username: "  alice  ", urls: [], fields: [
        { name: "public\r\nfield", value: plain, secret: false }, { name: "private\r\nfield", value: null, secret: true }
    ] } });
    await vm.runInContext("api.openItem(1);", env.context);
    assert.equal(env.elements.fields.querySelectorAll("textarea")[0].value, "public first\npublic second\nlast");
    env.elements.editForm.listeners.submit({ preventDefault() {} }); await flush();
    let write = env.calls.find(call => call.action === "managerUpdate");
    assert.equal(write.item.fields[0].value, plain);
    assert.equal(write.item.fields[0].name, "public\r\nfield");
    assert.equal(write.item.removeFields.length, 0);
    assert.equal(write.item.fields.length, 1);
    assert.equal(write.item.notes, "notes\r\nsecond line");
    assert.equal(write.item.username, "  alice  ");

    await vm.runInContext("api.openItem(1);", env.context);
    env.setResponse("managerItem", { success: true, data: { password: secret, fields: [{ name: "private\r\nfield", value: secret, secret: true }] } });
    env.elements.reveal.click(); await flush();
    const privateControl = env.elements.fields.querySelectorAll("textarea")[1];
    assert.equal(privateControl.value, "private first\nprivate second\nlast");
    assert.equal(env.elements.secretMultiline.value, "private first\nprivate second\nlast");
    env.calls.length = 0;
    env.elements.editForm.listeners.submit({ preventDefault() {} }); await flush();
    write = env.calls.find(call => call.action === "managerUpdate");
    assert.equal(write.item.password, secret);
    assert.equal(write.item.fields[1].value, secret);
    assert.equal(write.item.fields[1].name, "private\r\nfield");
});

test("revealed multiline custom values expire while user edits survive", async () => {
    const env = environment(); await flush();
    env.setResponse("managerItem", { success: true, data: { id: 1, name: "work", kind: "login", urls: [], fields: [
        { name: "private", value: null, secret: true }
    ] } });
    await vm.runInContext("api.openItem(1);", env.context);
    env.setResponse("managerItem", { success: true, data: { password: "", fields: [{ name: "private", value: "first\r\nsecond", secret: true }] } });
    env.elements.reveal.click(); await flush();
    const control = env.elements.fields.querySelectorAll("textarea")[0];
    for (const expire of env.timers.values()) expire();
    assert.equal(control.value, "");
    assert.equal(vm.runInContext("api.controlValue(api.fieldRows[0].value)", env.context), "");
    env.elements.reveal.click(); await flush();
    control.value = "edited\nvalue";
    for (const expire of env.timers.values()) expire();
    assert.equal(control.value, "edited\nvalue");
    assert.equal(vm.runInContext("api.renderedValues.has(api.fieldRows[0].value)", env.context), false);
    env.elements.editForm.listeners.submit({ preventDefault() {} }); await flush();
    assert.equal(env.calls.find(call => call.action === "managerUpdate").item.fields[0].value, "edited\nvalue");
});

test("uncertain manager mutations require explicit state review before another write", async () => {
    const env = environment(); await flush();
    env.setResponse("managerUpdate", { success: false, error: "Save may still complete. Review the vault.", uncertain: true, operationId: "mutation-123" });
    vm.runInContext('api.runMutation(() => api.send("managerUpdate", { entryId: 1 }));', env.context); await flush();
    assert.equal(env.elements.reviewOutcome.hidden, false);
    assert.match(env.elements.message.textContent, /may still complete/);
    const writes = () => env.calls.filter(call => call.action === "managerUpdate").length;
    vm.runInContext('api.runMutation(() => api.send("managerUpdate", { entryId: 1 }));', env.context); await flush();
    assert.equal(writes(), 1);
    env.setResponse("reconcileOperation", { success: false, error: "Review failed" });
    env.elements.reviewOutcome.click(); await flush();
    assert.equal(env.elements.reviewOutcome.hidden, false);
    assert.equal(env.elements.reviewOutcome.disabled, false);
    assert.match(env.elements.message.textContent, /Review failed/);
    env.setResponse("reconcileOperation", { success: true, data: { state: "committed", operationId: "mutation-123", revision: 2 } });
    env.elements.reviewOutcome.click(); await flush();
    assert.equal(env.elements.reviewOutcome.hidden, true);
    assert.match(env.elements.message.textContent, /change completed/);
    env.setResponse("managerUpdate", { success: true, data: "Saved" });
    vm.runInContext('api.runMutation(() => api.send("managerUpdate", { entryId: 1 }));', env.context); await flush();
    assert.equal(writes(), 2);
});

test("a failed unlock can be reviewed while locked without trapping the user", async () => {
    const env = environment(); await flush();
    env.setResponse("managerVaults", { success: true, data: ["example.enc"] });
    env.setResponse("managerUnlock", { success: false, error: "Unlock response lost", uncertain: true, operationId: "mutation-123" });
    vm.runInContext('api.runMutation(() => api.send("managerUnlock"));', env.context); await flush();
    env.setResponse("getStatus", { native: true, running: true, locked: true });
    env.setResponse("reconcileOperation", { success: true, data: { state: "committed", operationId: "mutation-123" } });
    env.elements.reviewOutcome.click(); await flush();
    assert.equal(env.elements.reviewOutcome.hidden, true);
    assert.match(env.elements.message.textContent, /change completed/);
});

test("Duo manager never approves from polling, requires typed code and clears it on lock", async () => {
    const env = environment(); await flush();
    await vm.runInContext("api.openItem(1);", env.context);
    await vm.runInContext("api.checkDuo();", env.context);
    assert.equal(env.calls.some(call => call.action === "managerDuoRespond"), false);
    assert.equal(env.elements.duo.hidden, false);
    const code = env.elements.duoRequests.querySelectorAll("input")[0];
    const approve = env.elements.duoRequests.querySelectorAll("button")[0];
    assert.equal(code.type, "password");
    approve.click(false); await flush();
    assert.equal(env.calls.some(call => call.action === "managerDuoRespond"), false);
    approve.click(); await flush();
    assert.equal(env.calls.some(call => call.action === "managerDuoRespond"), false);
    assert.equal(env.confirmations(), 0);
    code.value = "012";
    approve.click(); await flush();
    const decisions = env.calls.filter(call => call.action === "managerDuoRespond");
    assert.equal(decisions.length, 1);
    assert.equal(decisions[0].requestId, "test-request");
    assert.equal(decisions[0].verificationCode, "012");
    assert.equal(decisions[0].approve, true);
    assert.equal(env.confirmations(), 1);
    assert.equal(code.value, "");
    env.setPending([{ id: "second-request", application: "VPN", username: "alice", expires_at: Math.floor(Date.now()/1000)+300, code_digits: 3, unsupported: null, fingerprint: "b".repeat(128) }]);
    await vm.runInContext("api.checkDuo();", env.context);
    const secondCode = env.elements.duoRequests.querySelectorAll("input")[0]; secondCode.value = "123";
    env.elements.duoWatch.checked = true;
    await vm.runInContext("api.checkDuo();", env.context);
    assert.ok(env.timers.size > 0);
    env.lock();
    assert.equal(secondCode.value, "");
    assert.equal(env.elements.duoWatch.checked, false);
    assert.equal(env.elements.duoRequests.children.length, 0);
    assert.equal(env.timers.size, 0);
});

test("Duo manager offers denial while disabling unsupported approval", async () => {
    const env = environment(); await flush(); await vm.runInContext("api.openItem(1);", env.context);
    env.setPending([{ id: "restricted-request", application: "VPN", username: "alice", expires_at: Math.floor(Date.now()/1000)+300, code_digits: null, unsupported: "Requires proximity verification", fingerprint: "c".repeat(128) }]);
    await vm.runInContext("api.checkDuo();", env.context);
    const [approve, deny] = env.elements.duoRequests.querySelectorAll("button");
    assert.equal(approve.disabled, true); assert.equal(deny.disabled, false);
    deny.click(); await flush();
    const decision = env.calls.find(call => call.action === "managerDuoRespond");
    assert.equal(decision.approve, false); assert.equal(decision.verificationCode, "");
});

test("unknown item mutations require an unlocked item refresh and explicit acknowledgement, while pending remains blocked", async () => {
    const env = environment(); await flush();
    env.setResponse("managerUpdate", { success: false, error: "Reply lost", uncertain: true, operationId: "save-unknown" });
    vm.runInContext('api.runMutation(() => api.send("managerUpdate", { entryId: 1 }));', env.context); await flush();
    env.setResponse("reconcileOperation", { success: true, data: { state: "pending", operationId: "save-unknown" } });
    env.elements.reviewOutcome.click(); await flush();
    assert.equal(env.elements.acknowledgeUnknown.hidden, true);
    env.setResponse("reconcileOperation", { success: true, data: { state: "unknown", operationId: "save-unknown" } });
    env.elements.reviewOutcome.click(); await flush();
    assert.equal(env.elements.acknowledgeUnknown.hidden, false);
    env.setResponse("getStatus", { native: true, running: true, locked: true });
    env.elements.acknowledgeUnknown.click(); await flush();
    assert.match(env.elements.message.textContent, /unlocked vault/);
    assert.equal(env.calls.filter(call => call.action === "acknowledgeUnknownOperation").length, 0);
    env.setResponse("getStatus", { native: true, running: true, locked: false });
    env.setResponse("acknowledgeUnknownOperation", { success: true });
    env.elements.acknowledgeUnknown.click(); await flush();
    assert.equal(env.calls.filter(call => call.action === "acknowledgeUnknownOperation").length, 1);
    assert.equal(env.elements.reviewOutcome.hidden, true);
    assert.equal(env.calls.filter(call => call.action === "managerUpdate").length, 1);
});

test("unknown unlocks can be acknowledged after inspecting the published lock state", async () => {
    const env = environment(); await flush();
    env.setResponse("managerUnlock", { success: false, error: "Reply lost", uncertain: true, operationId: "unlock-unknown" });
    vm.runInContext('api.runMutation(() => api.send("managerUnlock"));', env.context); await flush();
    env.setResponse("getStatus", { native: true, running: true, locked: true });
    env.setResponse("reconcileOperation", { success: true, data: { state: "unknown", operationId: "unlock-unknown" } });
    env.elements.reviewOutcome.click(); await flush();
    env.setResponse("acknowledgeUnknownOperation", { success: true });
    env.elements.acknowledgeUnknown.click(); await flush();
    assert.equal(env.calls.filter(call => call.action === "acknowledgeUnknownOperation").length, 1);
    assert.equal(env.confirmations(), 1);
});

test("the manager clears the old editor after a missed lock/unlock and binds reads to its displayed session", async () => {
    const env = environment(); await flush(); await vm.runInContext("api.openItem(1);", env.context);
    assert.equal(env.calls.find(call => call.action === "managerItem").expectedSession, "a".repeat(64));
    env.elements.password.value = "old-session-secret";
    env.publishStatus({ native: true, running: true, locked: false, sessionId: "b".repeat(64) });
    await flush();
    assert.equal(env.elements.password.value, "");
    assert.equal(env.elements.editor.hidden, true);
    await vm.runInContext("api.openItem(1);", env.context);
    assert.equal(env.calls.filter(call => call.action === "managerItem").at(-1).expectedSession, "b".repeat(64));
});


test("manager keeps dirty drafts when switching, adding, or closing is canceled", async () => {
    const env = environment(); await flush(); await vm.runInContext("api.openItem(1)", env.context);
    env.elements.name.value = "Unsaved account";
    env.elements.editForm.listeners.input();
    env.setConfirm(false);
    const before = env.calls.length;
    await vm.runInContext("api.openItem(2)", env.context);
    env.elements.new.click(); env.elements.cancel.click();
    assert.equal(env.elements.name.value, "Unsaved account");
    assert.equal(env.calls.length, before, "canceled navigation must not request another item");
    assert.equal(env.confirmations(), 3);
    env.setConfirm(true); env.elements.cancel.click();
    assert.equal(env.elements.editor.hidden, true);
});

test("generator mode hides and disables irrelevant controls", async () => {
    const env = environment(); await flush();
    env.elements.genMode.value = "passphrase"; env.elements.genMode.listeners.change();
    assert.equal(env.elements.passwordOptions.hidden, true);
    assert.equal(env.elements.passwordOptions.disabled, true);
    assert.equal(env.elements.passphraseOptions.hidden, false);
    env.elements.genMode.value = "password"; env.elements.genMode.listeners.change();
    assert.equal(env.elements.passphraseOptions.disabled, true);
    assert.equal(env.elements.passwordOptions.hidden, false);
});


test("dirty drafts warn on page exit but never prevent lock cleanup", async () => {
    const env = environment(); await flush(); await vm.runInContext("api.openItem(1)", env.context);
    env.elements.editForm.listeners.input();
    let warned = false;
    env.windowEvents.get("beforeunload")({ preventDefault() { warned = true; } });
    assert.equal(warned, true);
    env.lock(); warned = false;
    env.windowEvents.get("beforeunload")({ preventDefault() { warned = true; } });
    assert.equal(warned, false);
    assert.equal(env.elements.editor.hidden, true);
    assert.equal(env.elements.password.value, "");
});


test("pending saves prevent editor interaction and navigation until the reply", async () => {
    const env = environment(); await flush(); await vm.runInContext("api.openItem(1)", env.context);
    let finish;
    env.setResponse("managerUpdate", (_request, callback) => { finish = callback; });
    env.elements.editForm.listeners.submit({ preventDefault() {} }); await flush();
    assert.equal(env.elements.editForm.inert, true);
    env.elements.new.click(); env.elements.cancel.click();
    assert.equal(env.elements.editor.hidden, false);
    assert.match(env.elements.message.textContent, /Wait/);
    finish({ success: true, data: "saved" }); await flush();
    assert.equal(env.elements.editForm.inert, false);
    assert.equal(env.elements.editor.hidden, true);
});

test("reveals offer immediate hiding without losing edits", async () => {
    const env = environment(); await flush(); await vm.runInContext("api.openItem(1)", env.context);
    env.setResponse("managerItem", { success: true, data: { password: "stored secret", fields: [] } });
    env.elements.reveal.click(); await flush();
    assert.match(env.elements.reveal.textContent, /Hide now/);
    env.elements.password.value = "my edited value";
    env.elements.reveal.click(); await flush();
    assert.equal(env.elements.password.value, "my edited value");
    assert.equal(env.elements.password.type, "password");
    assert.match(env.elements.reveal.textContent, /30 seconds/);
});


test("manager pages every match including items beyond the first hundred", async () => {
    const env = environment();
    const items = Array.from({length:151}, (_, index) => ({ id:index+1, name:`Item ${index}`, kind:"login" }));
    env.setResponse("managerList", (request, callback) => callback({ success:true, data:{ total:151, items:items.slice(request.offset || 0, (request.offset || 0) + 50) } }));
    await flush();
    assert.equal(env.elements.items.children.length, 50);
    env.elements.itemPage.value = "4"; env.elements.itemPage.listeners.change(); await flush();
    assert.equal(env.elements.items.children.length, 1);
    assert.match(env.elements.items.children[0].textContent, /Item 150/);
    env.elements.previousItems.click(); await flush();
    assert.equal(env.elements.items.children.length, 50);
});

test("the item list identifies the open item and clears selection on close", async () => {
    const env = environment();
    env.setResponse("managerList", {success:true,data:{total:1,items:[{id:1,name:"work",kind:"login"}]}});
    await flush(); await vm.runInContext("api.openItem(1)", env.context);
    assert.equal(env.elements.items.children[0].getAttribute("aria-pressed"),"true");
    env.elements.cancel.click();
    assert.equal(env.elements.items.children[0].getAttribute("aria-pressed"),"false");
});

test("a failed page request preserves the displayed page for retry", async () => {
    const env = environment();
    const items = Array.from({length:151}, (_, index) => ({id:index+1,name:`Item ${index}`,kind:"login"}));
    const respond = (request, callback) => callback({success:true,data:{total:items.length,items:items.slice(request.offset || 0,(request.offset || 0)+50)}});
    env.setResponse("managerList", respond); await flush();
    env.setResponse("managerList", {success:false,error:"Synthetic connection failure"});
    env.elements.nextItems.click(); await flush();
    assert.match(env.elements.count.textContent, /page 1 of 4/);
    env.setResponse("managerList", respond);
    env.elements.nextItems.click(); await flush();
    assert.match(env.elements.count.textContent, /page 2 of 4/);
    assert.match(env.elements.items.children[0].textContent, /Item 50/);
});

test("explicit list refresh discovers external items while preserving a dirty draft", async () => {
    const env = environment(); await flush();
    await vm.runInContext("api.openItem(1)", env.context);
    env.elements.name.value = "Unsaved local change"; env.elements.editForm.listeners.input();
    env.setResponse("managerList", {success:true,data:{total:1,items:[{id:2,name:"External addition",kind:"login"}]}});
    env.elements.refreshItems.click(); await flush();
    assert.equal(env.elements.name.value,"Unsaved local change");
    assert.equal(env.elements.editor.hidden,false);
    assert.match(env.elements.items.children[0].textContent,/External addition/);
    env.setConfirm(false); env.elements.cancel.click();
    assert.equal(env.elements.editor.hidden,false);
});

test("list refresh during add preserves the save completion and prevents duplicate drafts", async () => {
    const env = environment(); await flush(); env.elements.new.click();
    env.elements.name.value = "New draft"; env.elements.editForm.listeners.input();
    let finish;
    env.setResponse("managerAdd", (_request, callback) => { finish = callback; });
    env.elements.editForm.listeners.submit({preventDefault(){}}); await flush();
    env.elements.refreshItems.click(); await flush();
    finish({success:true,data:"saved"}); await flush();
    assert.equal(env.elements.editor.hidden,true);
    assert.equal(env.elements.editForm.inert,false);
    assert.equal(env.calls.filter(call => call.action === "managerAdd").length,1);
});

test("typed replacements reveal explicitly and hide on expiry without being erased", async () => {
    const env = environment(); await flush(); await vm.runInContext("api.openItem(1)", env.context);
    env.elements.password.value = "typed replacement";
    env.setResponse("managerItem", {success:true,data:{password:"old stored secret",fields:[]}});
    env.elements.reveal.click(); await flush();
    assert.equal(env.elements.password.type, "text");
    assert.equal(env.elements.password.value, "typed replacement");
    for (const expire of [...env.timers.values()]) expire();
    assert.equal(env.elements.password.type, "password");
    assert.equal(env.elements.password.value, "typed replacement");
});

test("a new draft can reveal its own secret without fetching another item", async () => {
    const env = environment(); await flush(); env.elements.new.click();
    env.elements.password.value = "new typed value"; env.elements.editForm.listeners.input();
    assert.equal(env.elements.reveal.disabled, false);
    const reads = env.calls.filter(call => call.action === "managerItem").length;
    env.elements.reveal.click(); await flush();
    assert.equal(env.elements.password.type, "text");
    assert.equal(env.calls.filter(call => call.action === "managerItem").length, reads);
    env.elements.reveal.click(); await flush();
    assert.equal(env.elements.password.value, "new typed value");
    assert.equal(env.elements.password.type, "password");
});

test("revision conflicts preserve edits and reapply onto the reviewed revision", async () => {
    const env = environment(); await flush();
    env.setResponse("managerItem", {success:true,data:{id:1,revision:1,name:"Original",username:"old owner",kind:"login",notes:"",urls:[],fields:[]}});
    await vm.runInContext("api.openItem(1)", env.context);
    env.elements.name.value = "My local edit"; env.elements.editForm.listeners.input();
    env.setResponse("managerUpdate", {success:false,code:4,error:"Item changed since opened"});
    env.elements.editForm.listeners.submit({preventDefault(){}}); await flush();
    assert.equal(env.elements.conflict.hidden, false);
    assert.equal(env.elements.name.value, "My local edit");
    assert.equal(env.elements.saveItem.disabled, true);
    env.setResponse("managerItem", {success:true,data:{id:1,revision:2,name:"Remote name",username:"remote owner",kind:"login",notes:"remote notes",urls:[],fields:[{name:"region",secret:false,value:"remote region"}]}});
    env.elements.reviewConflict.click(); await flush();
    assert.match(env.elements.conflictDiff.textContent, /also changed elsewhere/);
    env.elements.reapplyConflict.click(); await flush();
    assert.equal(env.elements.name.value, "My local edit");
    assert.equal(env.elements.username.value, "remote owner");
    assert.equal(env.elements.notes.value, "remote notes");
    env.setResponse("managerUpdate", {success:true,data:"saved"});
    env.elements.editForm.listeners.submit({preventDefault(){}}); await flush();
    const write = env.calls.filter(call => call.action === "managerUpdate").at(-1);
    assert.equal(write.expectedRevision, 2);
    assert.equal(write.item.fields[0].value, "remote region");
});
