const test = require("node:test");
const assert = require("node:assert/strict");

class FakeInput {
    constructor(type = "text", attributes = {}) {
        this.type = type;
        this.attributes = attributes;
        this.name = attributes.name || "";
        this.id = attributes.id || "";
        this.className = "";
        this.autocomplete = attributes.autocomplete || "";
        this.disabled = false;
        this.readOnly = false;
        this.isConnected = true;
        this.nodeType = 1;
        this.parentElement = null;
        this.form = null;
    }
    getAttribute(name) { return this.attributes[name] || null; }
    closest() { return null; }
}

class FakeForm {
    constructor(elements) {
        this.elements = elements;
        for (const element of elements) element.form = this;
    }
    querySelectorAll() { return this.elements; }
}

global.HTMLInputElement = FakeInput;
global.HTMLFormElement = FakeForm;
global.getComputedStyle = element => element.style || {
    display: "block", visibility: "visible", opacity: "1"
};
global.document = { body: {}, querySelectorAll() { return []; } };

const detection = require("./content_detection.js");

test("credential detection distinguishes login, registration, search, and TOTP fields", () => {
    const username = new FakeInput("email", { autocomplete: "username", "aria-label": "Email" });
    const password = new FakeInput("password", { autocomplete: "current-password" });
    const form = new FakeForm([username, password]);
    assert.equal(detection.isCredentialInput(username), true);
    assert.equal(detection.isCredentialInput(password), true);
    assert.deepEqual(detection.credentialFields(password), {
        scope: form, usernameField: username, passwordField: password
    });

    const registration = new FakeInput("password", { autocomplete: "new-password" });
    assert.equal(detection.isNewPasswordInput(registration), true);
    assert.equal(detection.isCredentialInput(registration), false);
    const confirmation = new FakeInput("password", { placeholder: "Repeat password" });
    assert.equal(detection.isNewPasswordInput(confirmation), true);

    const search = new FakeInput("search", { role: "searchbox", placeholder: "Find account" });
    assert.equal(detection.hasSearchHint(search), true);
    assert.equal(detection.isCredentialInput(search), false);
    const totp = new FakeInput("tel", { autocomplete: "one-time-code" });
    assert.equal(detection.isTotpInput(totp), true);
});

test("card security codes are not one-time sign-in codes", () => {
    assert.equal(detection.isTotpInput(new FakeInput("text", { name: "otp", "aria-label": "Security code" })), true);
    assert.equal(detection.isTotpInput(new FakeInput("text", { autocomplete: "cc-csc", "aria-label": "Security code" })), false);
    assert.equal(detection.isTotpInput(new FakeInput("tel", { name: "cvc", placeholder: "Security code" })), false);
    assert.equal(detection.isTotpInput(new FakeInput("text", { "aria-label": "Card security code" })), false);
    // Layout classes that merely mention "card" do not hide a sign-in code.
    const styled = new FakeInput("text", { name: "otp" });
    styled.className = "card-input";
    assert.equal(detection.isTotpInput(styled), true);
});

test("unlabelled usernames are accepted only immediately before a login password", () => {
    const unrelated = new FakeInput("text");
    const username = new FakeInput("text");
    const password = new FakeInput("password");
    new FakeForm([unrelated, username, password]);
    assert.equal(detection.isCredentialInput(unrelated), false);
    assert.equal(detection.isCredentialInput(username), true);
    assert.deepEqual(detection.usernameCandidates([unrelated, username, password]), [unrelated, username]);
});

test("hidden, disconnected, disabled, and readonly fields fail closed", () => {
    const input = new FakeInput("text", { name: "username" });
    assert.equal(detection.isElementVisible(input), true);
    input.style = { display: "none", visibility: "visible", opacity: "1" };
    assert.equal(detection.isUsableInput(input), false);
    input.style.display = "block";
    input.disabled = true;
    assert.equal(detection.isUsableInput(input), false);
    input.disabled = false;
    input.readOnly = true;
    assert.equal(detection.isUsableInput(input), false);
    input.readOnly = false;
    input.isConnected = false;
    assert.equal(detection.isElementVisible(input), false);
});

test("a transparent input is visible, but a transparent container hides it", () => {
    // Vuetify keeps unfocused inputs at opacity 0 behind a floating label.
    const input = new FakeInput("text", { placeholder: "Enter your email" });
    input.style = { display: "flex", visibility: "visible", opacity: "0" };
    assert.equal(detection.isUsableInput(input), true);
    const container = new FakeInput();
    container.style = { display: "block", visibility: "visible", opacity: "0" };
    input.parentElement = container;
    assert.equal(detection.isElementVisible(input), false);
});

test("scan-local form classification refreshes after fields change", () => {
    const unrelated = new FakeInput("text");
    const username = new FakeInput("text");
    const password = new FakeInput("password");
    const form = new FakeForm([unrelated, username, password]);
    let scans = 0;
    const elements = form.elements;
    Object.defineProperty(form, "elements", { get() { scans++; return elements; } });
    const cache = new WeakMap();
    assert.equal(detection.isCredentialInput(unrelated, cache), false);
    assert.equal(detection.isCredentialInput(username, cache), true);
    assert.equal(scans, 1);

    username.disabled = true;
    const nextScan = new WeakMap();
    assert.equal(detection.isCredentialInput(unrelated, nextScan), true);
    assert.equal(detection.isCredentialInput(username, nextScan), false);
    assert.equal(scans, 2);
    password.autocomplete = "new-password";
    assert.equal(detection.isCredentialInput(unrelated, new WeakMap()), false);
    assert.equal(detection.isCredentialInput(unrelated), false);
});


test("credential fields can resolve replaced anchors within their original scope", () => {
    const oldUsername = new FakeInput("text", { autocomplete: "username" });
    const oldPassword = new FakeInput("password");
    const form = new FakeForm([oldUsername, oldPassword]);
    const username = new FakeInput("text", { autocomplete: "username" });
    const password = new FakeInput("password");
    form.elements = [username, password];
    for (const input of [oldUsername, oldPassword]) {
        input.isConnected = false;
        input.form = null;
    }
    for (const anchor of [oldUsername, oldPassword]) {
        assert.deepEqual(detection.credentialFields(anchor, form), {
            scope: form, usernameField: username, passwordField: password
        });
    }
});

test("associated labels contribute identity field descriptors", () => {
    const input = new FakeInput("text", { id: "f1" });
    input.labels = [{ textContent: "First name" }];
    const fields = require("./content_fields.js");
    assert.equal(fields.inferIdentity(detection.inputDescriptors(input)), "given-name");
    input.labels = [{ textContent: "Last name" }];
    assert.equal(fields.inferIdentity(detection.inputDescriptors(input)), "family-name");
});

test("login selection and capture exclude identity and one-time-code fields", () => {
    const first = new FakeInput("text", { autocomplete: "given-name" });
    const last = new FakeInput("text", { autocomplete: "family-name" });
    const code = new FakeInput("tel", { autocomplete: "one-time-code" });
    const username = new FakeInput("email", { autocomplete: "username" });
    const password = new FakeInput("password");
    const form = new FakeForm([first, last, username, code, password]);
    assert.deepEqual(detection.usernameCandidates(form.elements), [username]);
    assert.equal(detection.credentialFields(password).usernameField, username);
    assert.equal(detection.isCredentialInput(code), false);
    assert.equal(detection.isCredentialInput(last), false);
});

test("multiple login pairs in a shared form use the fields closest to the selected anchor", () => {
    const firstUser = new FakeInput("text", { autocomplete: "username" });
    const firstPassword = new FakeInput("password", { autocomplete: "current-password" });
    const secondUser = new FakeInput("text", { autocomplete: "username" });
    const secondPassword = new FakeInput("password", { autocomplete: "current-password" });
    new FakeForm([firstUser, firstPassword, secondUser, secondPassword]);
    for (const anchor of [secondUser, secondPassword]) {
        const fields = detection.credentialFields(anchor);
        assert.equal(fields.usernameField, secondUser);
        assert.equal(fields.passwordField, secondPassword);
    }
});

test("saving a shared form captures the selected login pair rather than another filled account", () => {
    const firstUser = new FakeInput("text", { autocomplete: "username" });
    const firstPassword = new FakeInput("password", { autocomplete: "current-password" });
    const secondUser = new FakeInput("text", { autocomplete: "username" });
    const secondPassword = new FakeInput("password", { autocomplete: "current-password" });
    [firstUser.value, firstPassword.value, secondUser.value, secondPassword.value] =
        ["first", "first-secret", "second", "second-secret"];
    const form = new FakeForm([firstUser, firstPassword, secondUser, secondPassword]);
    const credentials = require("./content_credentials.js").create();
    credentials.lastInput = secondPassword;
    assert.deepEqual(credentials.findLoginCredentials(form), {
        username: "second", password: "second-secret", passwordField: secondPassword, newPassword: false, scope: form
    });
});

test("visibility caches share ancestor reads only within a synchronous scan", () => {
    const original = global.getComputedStyle;
    let reads = 0;
    global.getComputedStyle = element => { reads++; return original(element); };
    try {
        const parent = new FakeInput();
        const first = new FakeInput(), second = new FakeInput();
        first.parentElement = parent; second.parentElement = parent;
        detection.withVisibilityCache(() => {
            assert.equal(detection.isElementVisible(first), true);
            assert.equal(detection.isElementVisible(second), true);
        });
        assert.equal(reads, 3);
        parent.style = { display: "none", visibility: "visible", opacity: "1" };
        assert.equal(detection.isElementVisible(first), false);
        assert.throws(() => detection.withVisibilityCache(() => { throw new Error("stop"); }), /stop/);
        parent.style.display = "block";
        assert.equal(detection.isElementVisible(first), true);
    } finally { global.getComputedStyle = original; }
});

test("typed identity context is shared per scan and refreshed on the next scan", () => {
    const { typedAutofillKind } = require("./content_autofill.js").create({ bridge: {} });
    const email = new FakeInput("email", { autocomplete: "section-a email" });
    const phone = new FakeInput("tel", { autocomplete: "section-a tel" });
    const otherGroup = new FakeInput("email", { autocomplete: "section-b email" });
    const name = new FakeInput("text", { autocomplete: "section-a name" });
    const form = new FakeForm([email, phone, otherGroup, name]);
    const fields = form.elements;
    let scans = 0;
    Object.defineProperty(form, "elements", { get() { scans++; return fields; } });
    const cache = new WeakMap();
    assert.equal(typedAutofillKind(email, cache), "identity");
    assert.equal(typedAutofillKind(phone, cache), "identity");
    assert.equal(typedAutofillKind(otherGroup, cache), null);
    assert.equal(scans, 1);
    name.disabled = true;
    assert.equal(typedAutofillKind(email, new WeakMap()), null);
    assert.equal(scans, 2);
});

test("form-less credential scopes walk up to the nearest container with both roles and stop early", () => {
    const original = global.getComputedStyle;
    let reads = 0;
    global.getComputedStyle = element => {
        reads++;
        return original(element);
    };
    try {
        const container = (inputs, parentElement = null) => ({
            parentElement,
            querySelectorAll: selector => {
                assert.equal(selector, "input");
                return inputs;
            },
        });
        const search = new FakeInput("search", { placeholder: "Search" });
        const username = new FakeInput("email", { autocomplete: "username" });
        const password = new FakeInput("password");
        const trailing = Array.from({ length: 50 }, () => new FakeInput("text"));
        const outer = container([search, username, password, ...trailing]);
        const inner = container([password], outer);
        password.parentElement = inner;
        const scope = detection.withVisibilityCache(() => detection.credentialScope(password));
        assert.equal(scope, outer);
        // The password's style is read once per scan; the search field fails its
        // type check without a style read; trailing inputs are never inspected.
        assert.equal(reads, 2);
        assert.equal(detection.credentialScope(Object.assign(new FakeInput("password"), { parentElement: null })), document);
    } finally {
        global.getComputedStyle = original;
    }
});

test("password visibility toggles are recognized from their descriptors", () => {
    const control = (attributes = {}, text = "") => ({
        id: attributes.id || "",
        textContent: text,
        getAttribute: name => attributes[name] ?? null,
        hasAttribute: name => name in attributes,
    });
    for (const [label, candidate] of [
        ["aria label", control({ "aria-label": "Show password" })],
        ["title", control({ title: "Hide password" })],
        ["class", control({ class: "btn password-reveal" })],
        ["camel-case id", control({ id: "passwordEye" })],
        ["eye icon class", control({ class: "eye-icon" })],
        ["pressed state", control({ "aria-pressed": "false" })],
        ["text", control({}, "Show")],
        ["test id", control({ "data-testid": "toggle-visibility" })],
    ]) {
        assert.equal(detection.isVisibilityToggle(candidate), true, label);
    }
    const input = new FakeInput("button");
    input.value = "Unmask";
    input.hasAttribute = () => false;
    input.textContent = "";
    assert.equal(detection.isVisibilityToggle(input), true, "input value");
    for (const [label, candidate] of [
        ["sign in", control({ class: "btn primary" }, "Sign in")],
        ["next", control({ id: "next" }, "Next")],
        ["keyed class", control({ class: "keyed-submit" }, "Continue")],
        ["long text mentioning show", control({}, "Continue to the dashboard and show my account overview now")],
        ["missing", null],
    ]) {
        assert.equal(detection.isVisibilityToggle(candidate), false, label);
    }
});

test("extension UI is recognized by registration, not by page-controlled names", () => {
    const host = {};
    assert.equal(detection.isExtensionUi(host), false);
    assert.equal(detection.markExtensionUi(host), host);
    assert.equal(detection.isExtensionUi(host), true);
    assert.equal(detection.isExtensionUi({ className: "my-extension-ui", localName: "pm-field-control" }), false);
    assert.equal(detection.isExtensionUi(null), false);
});
