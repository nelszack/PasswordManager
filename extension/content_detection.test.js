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
