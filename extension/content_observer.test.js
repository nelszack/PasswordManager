const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

class Element {
    constructor(children = []) {
        this.nodeType = 1;
        this.isConnected = true;
        this.children = children;
        this.scans = 0;
        for (const child of children) child.parentNode = this;
    }
    querySelectorAll(selector) {
        assert.equal(selector, "*");
        this.scans++;
        return this.children.flatMap(child => [child, ...child.descendants()]);
    }
    descendants() { return this.children.flatMap(child => [child, ...child.descendants()]); }
}
class Input extends Element {
    constructor(kind = "login") {
        super();
        this.kind = kind;
        this.type = "text";
        this.classList = { contains: () => false };
    }
}

function environment(children = []) {
    const document = new Element(children);
    const frames = [];
    const controls = [];
    const observed = [];
    let notify;
    const context = {
        document,
        HTMLInputElement: Input,
        MutationObserver: class {
            constructor(callback) { notify = callback; }
            observe(root, options) { observed.push({ root, options }); }
        },
        requestAnimationFrame: callback => frames.push(callback),
        typedAutofillKind: input => input.kind === "card" ? "payment-card" : null,
        isTotpInput: input => input.kind === "totp",
        isCredentialInput: input => input.kind === "login",
        isUsableInput: input => input.isConnected && !input.disabled,
        isNewPasswordInput: () => false,
        createSecureTotpButton: input => controls.push([input, "totp"]),
        createSecureTypedButton: input => controls.push([input, "card"]),
        createSecureCredentialButton: input => controls.push([input, "login"]),
        removeSecurePickerButton: input => controls.push([input, "remove"]),
        createGeneratorButton: () => assert.fail("unexpected generator")
    };
    vm.createContext(context);
    const filename = require.resolve("./content_observer.js");
    vm.runInContext(fs.readFileSync(filename, "utf8"), context, { filename });
    context.observeInputs();
    return {
        document, controls, observed, frames,
        notify: mutations => notify(mutations),
        flush: () => frames.shift()()
    };
}

function added(...nodes) { return { type: "childList", addedNodes: nodes }; }

test("initial discovery visits nested open shadow roots and preserves control classification", () => {
    const login = new Input();
    const totp = new Input("totp");
    const card = new Input("card");
    const other = new Input("other");
    const nestedHost = new Element();
    nestedHost.shadowRoot = new Element([totp, card]);
    nestedHost.shadowRoot.host = nestedHost;
    const host = new Element([login]);
    host.shadowRoot = new Element([nestedHost, other]);
    host.shadowRoot.host = host;
    const env = environment([host]);
    assert.deepEqual(env.controls, [[login, "login"], [other, "remove"], [totp, "totp"], [card, "card"]]);
    assert.deepEqual(env.observed.map(item => item.root), [env.document, host.shadowRoot, nestedHost.shadowRoot]);
    for (const item of env.observed) {
        assert.equal(item.root.scans, 1);
        assert.equal(item.options.subtree, true);
        assert.ok(item.options.attributeFilter.includes("readonly"));
    }
});

test("one mutation frame coalesces overlapping roots across shadow boundaries in either order", () => {
    for (const parentFirst of [false, true]) {
        const env = environment();
        const input = new Input();
        const child = new Element([input]);
        const host = new Element();
        host.shadowRoot = new Element([child]);
        host.shadowRoot.host = host;
        host.parentNode = env.document;
        env.document.children.push(host);
        env.notify([added(...(parentFirst ? [host, child, input] : [input, child, host]))]);
        assert.equal(env.frames.length, 1);
        env.flush();
        assert.deepEqual(env.controls, [[input, "login"]]);
        assert.equal(host.scans, 1);
        assert.equal(host.shadowRoot.scans, 1);
        assert.equal(child.scans, 0);
        assert.equal(input.scans, 0);
    }
});

test("input attribute changes reclassify controls and detached additions are skipped", () => {
    const input = new Input();
    const env = environment([input]);
    env.controls.length = 0;
    input.kind = "other";
    const detached = new Input();
    detached.isConnected = false;
    env.notify([{ type: "attributes", target: input, addedNodes: [] }, added(detached)]);
    env.flush();
    assert.deepEqual(env.controls, [[input, "remove"]]);
    assert.equal(detached.scans, 0);
});
