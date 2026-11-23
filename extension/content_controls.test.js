const test = require("node:test");
const assert = require("node:assert/strict");
const { installDom } = require("./test_dom.cjs");
const { create, positionedButton, controlButton, toastHost } = require("./content_controls.js");
const detection = require("./content_detection.js");

const noAutofill = { fillTypedItem() {}, typedFillContext: () => ({}) };

test("credential filling preserves literal None usernames and omits only absent values", () => {
    const { accountUsername } = create({ bridge: {}, credentials: {}, autofill: {} });
    for (const username of ["None", "  username  ", "", null, undefined]) {
        assert.equal(accountUsername({ username }), username || "");
    }
});

test("position measurements defer writes and unchanged positions avoid style mutation", t => {
    const dom = installDom(t);
    const input = dom.input("text", { left: 20, width: 100, height: 20, right: 120, top: 10 });
    dom.document.body.appendChild(input);
    const { host } = controlButton("key", "Choose saved credentials");
    const position = positionedButton(input, host, 30);
    const writes = dom.document.styleWrites;
    const apply = position.measure();
    assert.equal(dom.document.styleWrites, writes);
    apply();
    assert.equal(host.style.left, "90px");
    assert.equal(host.style.top, "6px");
    assert.equal(host.style.display, "block");
    assert.equal(host.style.getPropertyPriority("left"), "important", "page !important rules cannot move controls");
    const before = dom.document.styleWrites;
    position();
    assert.equal(dom.document.styleWrites, before);
    input.remove();
    position();
    assert.equal(host.style.display, "none");
});

test("controls inside a containing block other than the viewport still sit on the field", t => {
    // Vuetify 3 fields use `contain: layout`, which re-anchors fixed descendants.
    const dom = installDom(t);
    const input = dom.input("text", { left: 472, width: 336, height: 56, right: 808, top: 278 });
    dom.document.body.appendChild(input);
    const controls = create({ bridge: {}, credentials: {}, autofill: {} });
    t.after(() => controls.dispose());
    const { host } = controlButton("key", "Choose saved credentials");
    host.containingOrigin = { x: 472, y: 278 };
    controls.registerPositionedControl(input, host, positionedButton(input, host, 30));
    dom.flushFrames();
    dom.flushFrames();
    assert.deepEqual(
        [host.getBoundingClientRect().left, host.getBoundingClientRect().top],
        [778, 292],
        "the shown control is measured again and moved onto the field"
    );
    assert.equal(dom.frames.length, 0, "a placed control needs no further frames");
    dom.fireWindow("scroll");
    dom.flushFrames();
    assert.equal(host.getBoundingClientRect().left, 778, "the measured origin is kept");
});

test("layout frames measure every control before applying any position", t => {
    const dom = installDom(t);
    const work = [];
    const controls = create({ bridge: {}, credentials: {}, autofill: {} });
    t.after(() => controls.dispose());
    for (const id of [1, 2]) {
        const position = () => assert.fail("unbatched position");
        position.measure = layout => {
            work.push(`read ${id} ${layout}`);
            return () => work.push(`write ${id}`);
        };
        controls.registerPositionedControl({ isConnected: true }, { remove() {} }, position);
    }
    assert.equal(dom.frames.length, 1, "discovery schedules one shared layout frame");
    assert.deepEqual(work, [], "registering controls performs no geometry work");
    dom.fireWindow("resize");
    dom.fireWindow("scroll");
    controls.layoutChanged();
    assert.equal(dom.frames.length, 1);
    dom.flushFrames();
    assert.deepEqual(work, ["read 1 true", "read 2 true", "write 1", "write 2"]);
    work.length = 0;
    dom.fireWindow("scroll");
    dom.flushFrames();
    assert.deepEqual(work, ["read 1 false", "read 2 false", "write 1", "write 2"], "scrolling skips layout work");
});

test("controls step left of site icons and repeat the hit test only for layout changes", t => {
    const dom = installDom(t);
    const input = dom.input("text", { left: 20, width: 100, height: 20, right: 120, top: 10 });
    dom.document.body.appendChild(input);
    const { host } = controlButton("key", "Choose saved credentials");
    const siteIcon = dom.document.createElement("span");
    let probes = 0;
    dom.document.elementsFromPoint = () => {
        probes++;
        return dom.document.hits;
    };
    const position = positionedButton(input, host, 30);
    dom.document.hits = [host, input];
    position();
    assert.equal(host.style.left, "90px");
    dom.document.hits = [host, siteIcon];
    position.measure(true)();
    assert.equal(host.style.left, "58px", "site icon on top");
    dom.document.hits = [host, input];
    position.measure(false)();
    assert.equal(host.style.left, "58px", "scroll reuses the cached overlay shift");
    assert.equal(probes, 2);
    dom.document.hits = [{ contains: node => node === input }];
    position.measure(true)();
    assert.equal(host.style.left, "90px", "ancestor wrapper");
    dom.document.hits = [];
    position();
    assert.equal(host.style.left, "90px");

    // Off-screen fields cannot be hit tested; test again once they scroll into view.
    input.rect = { left: 20, width: 100, height: 20, right: 120, top: 2000 };
    const offscreen = positionedButton(input, host, 30);
    offscreen.measure(true)();
    const probesBefore = probes;
    input.rect = { left: 20, width: 100, height: 20, right: 120, top: 10 };
    dom.document.hits = [siteIcon];
    offscreen.measure(false)();
    assert.equal(probes, probesBefore + 1);
    assert.equal(host.style.left, "58px");
});

test("controls live in a closed shadow root after their field and keep their accessible names", t => {
    const dom = installDom(t);
    const form = dom.document.createElement("form");
    const input = dom.input();
    const next = dom.input("password");
    form.append(input, next);
    dom.document.body.appendChild(form);
    const opened = [];
    const controls = create({
        bridge: {
            fillInput() {},
            openSecurePicker: kind => {
                opened.push(kind);
                return Promise.resolve(null);
            },
        },
        credentials: { storeUsernameForLater() {} },
        autofill: noAutofill,
    });
    t.after(() => controls.dispose());
    controls.createSecureTotpButton(input);
    const host = input.nextElementSibling;
    assert.equal(host.localName, "pm-field-control");
    assert.equal(detection.isExtensionUi(host), true);
    assert.equal(host.shadowRoot, null, "the page cannot reach into the control");
    assert.equal(host.attachedShadow.mode, "closed");
    assert.equal(host.getAttribute("class"), null);
    const button = host.attachedShadow.querySelectorAll("button")[0];
    assert.equal(button.type, "button");
    assert.equal(button.getAttribute("aria-label"), "Choose one-time code");
    assert.equal(button.title, "Choose one-time code");
    assert.match(host.attachedShadow.querySelectorAll("style")[0].textContent, /focus-visible/);
    dom.flushFrames();
    assert.equal(host.style.display, "block");

    controls.createSecureTotpButton(input);
    assert.equal(form.children.length, 3, "the same kind reuses its control");
    button.click({ isTrusted: false });
    assert.deepEqual(opened, []);
    button.click();
    assert.deepEqual(opened, ["totp"]);

    controls.removeSecurePickerButton(input);
    assert.equal(form.children.length, 2);
    controls.createSecureTypedButton(next, "payment-card");
    controls.createSecureTypedButton(next, "identity");
    assert.equal(form.children.length, 3, "changing kind replaces the control");
    assert.equal(
        next.nextElementSibling.attachedShadow.querySelectorAll("button")[0].getAttribute("aria-label"),
        "Choose identity"
    );
    controls.dispose();
    assert.equal(form.children.length, 2, "dispose removes every control");
});

test("tests can opt into open shadow roots only from the extension's own content-script world", t => {
    const dom = installDom(t);
    globalThis.__pmTestOpenShadowRoots = true;
    t.after(() => delete globalThis.__pmTestOpenShadowRoots);
    const { host, button } = controlButton("key", "Choose saved credentials");
    assert.equal(host.shadowRoot.mode, "open");
    assert.equal(host.shadowRoot.querySelectorAll("button")[0], button);
    const toast = toastHost("Saved", 8, 40);
    dom.document.body.appendChild(toast);
    assert.equal(toast.shadowRoot.querySelectorAll("div")[0].getAttribute("role"), "status");
    assert.equal(toast.style.left, "8px");
    assert.equal(detection.isExtensionUi(toast), true);
});

test("picker failures show a temporary warning, and credential selections fill within the original scope", async t => {
    const dom = installDom(t);
    const timers = [];
    const previousSetTimeout = global.setTimeout;
    global.setTimeout = callback => timers.push(callback);
    t.after(() => (global.setTimeout = previousSetTimeout));
    const form = dom.document.createElement("form");
    const username = dom.input("email");
    username.autocomplete = "username";
    const password = dom.input("password");
    password.autocomplete = "current-password";
    form.append(username, password);
    dom.document.body.appendChild(form);
    const filled = [];
    let result = Promise.reject(new Error("Vault locked"));
    result.catch(() => {});
    const stored = [];
    const controls = create({
        bridge: { fillInput: (input, value) => filled.push([input, value]), openSecurePicker: () => result },
        credentials: { storeUsernameForLater: value => stored.push(value) },
        autofill: noAutofill,
    });
    t.after(() => controls.dispose());
    controls.createSecureCredentialButton(username);
    const button = username.nextElementSibling.attachedShadow.querySelectorAll("button")[0];
    button.click();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(button.dataset.icon, "warning");
    assert.equal(button.getAttribute("aria-label"), "Choose saved credentials: Vault locked");
    timers.shift()();
    assert.equal(button.dataset.icon, "key");
    assert.equal(button.getAttribute("aria-label"), "Choose saved credentials");

    result = Promise.resolve({ username: "alice", password: "secret" });
    button.click();
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(stored, ["alice"]);
    assert.deepEqual(filled, [
        [username, "alice"],
        [password, "secret"],
    ]);
    assert.equal(dom.document.activeElement, password);

    form.remove();
    button.click();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(filled.length, 2, "a removed form is never filled");
});

test("the fill shortcut opens the focused field's picker, else the first visible login field", async t => {
    const dom = installDom(t);
    const form = dom.document.createElement("form");
    const username = dom.input("email");
    const code = dom.input();
    form.append(username, code);
    dom.document.body.appendChild(form);
    const opened = [];
    const controls = create({
        bridge: {
            fillInput() {},
            openSecurePicker: kind => {
                opened.push(kind);
                return Promise.resolve(null);
            },
        },
        credentials: { storeUsernameForLater() {} },
        autofill: noAutofill,
    });
    t.after(() => controls.dispose());
    assert.equal(controls.activateShortcut(null), false, "no controls on the page");
    const claim = () => Promise.resolve({ username: "u", password: "p" });
    assert.equal(await controls.fillFromPopup(null, claim), false, "the popup needs a login form");
    controls.createSecureTotpButton(code);
    dom.flushFrames();
    assert.equal(controls.activateShortcut(null), false, "only login pickers are a fallback");
    assert.equal(await controls.fillFromPopup(code, claim), false, "a focused code field is not a login form");
    assert.equal(controls.activateShortcut(code), true, "a focused field uses its own picker");
    controls.createSecureCredentialButton(username);
    dom.flushFrames();
    assert.equal(controls.activateShortcut(null), true);
    assert.equal(controls.activateShortcut(dom.document.body), true, "unrelated focus falls back");
    assert.deepEqual(opened, ["totp", "login", "login"]);
});
