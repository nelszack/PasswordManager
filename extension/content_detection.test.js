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
        username: "second", password: "second-secret", scope: form
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
