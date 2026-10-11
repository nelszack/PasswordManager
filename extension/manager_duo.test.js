const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

class Element {
    constructor(tag = "div") { this.tag = tag; this.children = []; this.listeners = {}; this.value = ""; this.hidden = false; this.disabled = false; this.checked = false; this.textContent = ""; this.isConnected = true; }
    addEventListener(type, handler) { this.listeners[type] = handler; }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { for (const child of this.children) child.isConnected = false; this.children = children; }
    querySelectorAll(selectors) { return this.children.flatMap(child => [ ...(selectors.split(",").includes(child.tag) ? [child] : []), ...child.querySelectorAll(selectors) ]); }
    setAttribute() {}
    reset() {}
    click(trusted = true) { this.listeners.click?.({ preventDefault() {}, isTrusted: trusted }); }
}
function environment() {
    const html = fs.readFileSync(path.join(__dirname, "manager.html"), "utf8");
    const elements = Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(match => [match[1], new Element()]));
    elements.password.parentElement = new Element();
    const calls = [], timers = new Map(); let timerId = 0, confirmations = 0, listener;
    let pending = [{ id: "test-request", application: "Example VPN", username: "alice", location: "Boise", summary: "Login", expires_at: Math.floor(Date.now()/1000)+300, code_digits: 3, unsupported: null, fingerprint: "a".repeat(128) }];
    const context = vm.createContext({ document: { getElementById: id => elements[id], createElement: tag => new Element(tag), createTextNode: () => new Element() },
        window: { addEventListener() {}, confirm: () => { confirmations++; return true; } },
        setTimeout: callback => { timers.set(++timerId, callback); return timerId; }, clearTimeout: id => timers.delete(id),
        PasswordManagerGenerator: { defaults: {}, validate: () => ({}) },
        chrome: { runtime: { onMessage: { addListener: handler => { listener = handler; } }, sendMessage: (request, callback) => {
            calls.push(request);
            if (request.action === "getStatus") { callback({ native: true, running: true, locked: false }); return; }
            let data;
            if (request.action === "managerList") data = { total: 0, items: [] };
            if (request.action === "managerItem") data = { id: 1, name: "work", kind: "login", fields: [], urls: [], has_duo: true };
            if (request.action === "managerDuoRequests") data = pending;
            if (request.action === "managerDuoRespond") { data = request.approve ? "approved" : "denied"; pending = []; }
            callback({ success: true, data });
        } }, storage: { local: { get: (_key, callback) => callback?.({}) } } }
    });
    vm.runInContext(fs.readFileSync(path.join(__dirname, "manager.js"), "utf8"), context);
    return { context, elements, calls, timers, setPending: value => { pending = value; }, lock: () => listener({ action: "statusChanged", status: { native: true, running: true, locked: true } }), confirmations: () => confirmations };
}
const flush = () => new Promise(resolve => setImmediate(resolve));

test("Duo manager never approves from polling, requires typed code and clears it on lock", async () => {
    const env = environment(); await flush();
    await vm.runInContext("openItem(1);", env.context);
    await vm.runInContext("checkDuo();", env.context);
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
    await vm.runInContext("checkDuo();", env.context);
    const secondCode = env.elements.duoRequests.querySelectorAll("input")[0]; secondCode.value = "123";
    env.elements.duoWatch.checked = true;
    await vm.runInContext("checkDuo();", env.context);
    assert.ok(env.timers.size > 0);
    env.lock();
    assert.equal(secondCode.value, "");
    assert.equal(env.elements.duoWatch.checked, false);
    assert.equal(env.elements.duoRequests.children.length, 0);
    assert.equal(env.timers.size, 0);
});

test("Duo manager offers denial while disabling unsupported approval", async () => {
    const env = environment(); await flush(); await vm.runInContext("openItem(1);", env.context);
    env.setPending([{ id: "restricted-request", application: "VPN", username: "alice", expires_at: Math.floor(Date.now()/1000)+300, code_digits: null, unsupported: "Requires proximity verification", fingerprint: "c".repeat(128) }]);
    await vm.runInContext("checkDuo();", env.context);
    const [approve, deny] = env.elements.duoRequests.querySelectorAll("button");
    assert.equal(approve.disabled, true); assert.equal(deny.disabled, false);
    deny.click(); await flush();
    const decision = env.calls.find(call => call.action === "managerDuoRespond");
    assert.equal(decision.approve, false); assert.equal(decision.verificationCode, "");
});
