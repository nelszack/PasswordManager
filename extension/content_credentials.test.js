const test = require("node:test");
const assert = require("node:assert/strict");
const { installDom } = require("./test_dom.cjs");

function credentialsEnvironment(t, { top = true, pending = null, failing = false } = {}) {
    const messages = [];
    const location = { href: "https://login.example/signin" };
    const dom = installDom(t, {
        location,
        chrome: {
            runtime: {
                get lastError() {
                    return failing ? { message: "Receiving end does not exist" } : null;
                },
                sendMessage(message, callback) {
                    messages.push(message);
                    callback?.({ success: true, pending });
                },
            },
        },
    });
    dom.window.location = location;
    dom.window.top = top ? dom.window : {};
    const { create } = require("./content_credentials.js");
    const credentials = create({ roots: () => [dom.document] });
    const field = (parent, type, attributes = {}, value = "") => {
        const input = dom.input(type);
        for (const [name, attribute] of Object.entries(attributes)) {
            // Reflected properties such as name and autocomplete are plain fields here.
            if (name in input) input[name] = attribute;
            else input.setAttribute(name, attribute);
        }
        input.value = value;
        parent.appendChild(input);
        return input;
    };
    return { dom, credentials, messages, location, field };
}

test("captured credentials prefer new passwords, the selected login, then current-password fields", t => {
    const env = credentialsEnvironment(t);
    const form = env.dom.document.body.appendChild(env.dom.document.createElement("form"));
    const username = env.field(form, "email", { autocomplete: "username" }, " alice@example.com ");
    const current = env.field(form, "password", { autocomplete: "current-password" }, "old-secret");
    const fresh = env.field(form, "password", { autocomplete: "new-password" }, "new-secret");
    const confirm = env.field(form, "password", { placeholder: "Confirm password" }, "new-secret");
    assert.deepEqual(env.credentials.findLoginCredentials(form), {
        username: "alice@example.com",
        password: "new-secret",
        passwordField: fresh,
        newPassword: true,
        scope: form,
    });
    fresh.value = "";
    assert.equal(
        env.credentials.findLoginCredentials(form).passwordField,
        confirm,
        "a confirmation field is a last resort"
    );
    confirm.value = "";
    assert.equal(
        env.credentials.findLoginCredentials(username).password,
        "old-secret",
        "an input source uses its scope"
    );
    current.value = "";
    assert.deepEqual(env.credentials.findLoginCredentials(form), { username: "", password: "", scope: form });
});

test("without a source, capture uses the last credential input, then any filled password on the page", t => {
    const env = credentialsEnvironment(t);
    const { document } = env.dom;
    const first = document.body.appendChild(document.createElement("form"));
    env.field(first, "email", { autocomplete: "username" }, "first@example.com");
    const firstPassword = env.field(first, "password", {}, "");
    const second = document.body.appendChild(document.createElement("form"));
    env.field(second, "email", { autocomplete: "username" }, "second@example.com");
    const hidden = env.field(second, "password", {}, "hidden-secret");
    hidden.hiddenForTest = true;
    const visible = env.field(second, "password", {}, "second-secret");

    env.credentials.lastInput = firstPassword;
    assert.equal(env.credentials.lastInput, firstPassword);
    const found = env.credentials.findLoginCredentials();
    assert.equal(found.username, "second@example.com", "an empty recent field falls back to the page scan");
    assert.equal(found.passwordField, visible);
    firstPassword.value = "first-secret";
    assert.equal(env.credentials.findLoginCredentials().username, "first@example.com");
    visible.value = "";
    firstPassword.value = "";
    assert.deepEqual(env.credentials.findLoginCredentials(), { username: "", password: "", scope: null });
});

test("usernames prefer explicit autocomplete, then hints, then the last filled candidate", t => {
    const env = credentialsEnvironment(t);
    const { document } = env.dom;
    const scope = document.body.appendChild(document.createElement("div"));
    env.field(scope, "text", {}, "plain");
    assert.equal(env.credentials.usernameFromScope(scope), "plain");
    env.field(scope, "text", { name: "login" }, "hinted");
    env.field(scope, "text", {}, "later");
    assert.equal(env.credentials.usernameFromScope(scope), "hinted");
    env.field(scope, "email", { autocomplete: "email" }, " explicit@example.com ");
    assert.equal(env.credentials.usernameFromScope(scope), "explicit@example.com");
    assert.equal(env.credentials.usernameFromScope(document.body.appendChild(document.createElement("div"))), "");
});

test("remembered usernames stay on their origin and cross navigation only from the top frame", async t => {
    const env = credentialsEnvironment(t, { pending: { username: "restored@example.com" } });
    await env.credentials.restoreUsernameFromPreviousStep();
    assert.equal(env.credentials.resolveUsername(""), "restored@example.com");
    assert.equal(env.credentials.resolveUsername("typed"), "typed");
    env.location.href = "https://other.example/";
    assert.equal(env.credentials.resolveUsername(""), "", "another origin never receives the username");
    env.location.href = "https://login.example/next";
    env.credentials.rememberUsernameAcrossNavigation("alice");
    assert.deepEqual(env.messages.at(-1), { action: "setPendingCredentials", pending: { username: "alice" } });
    env.credentials.storeUsernameForLater("");
    assert.equal(env.credentials.resolveUsername(""), "");
    env.credentials.rememberUsernameAcrossNavigation("");
    assert.equal(env.messages.length, 2, "an empty username is cleared locally only");
    env.credentials.storeUsernameForLater("bob");
    env.credentials.lastInput = {};
    env.credentials.dispose();
    assert.equal(env.credentials.resolveUsername(""), "");
    assert.equal(env.credentials.lastInput, null);
});

test("embedded frames keep usernames local", async t => {
    const frame = credentialsEnvironment(t, { top: false, pending: { username: "x" } });
    await frame.credentials.restoreUsernameFromPreviousStep();
    frame.credentials.rememberUsernameAcrossNavigation("frame-user");
    assert.deepEqual(frame.messages, []);
    assert.equal(frame.credentials.resolveUsername(""), "frame-user");
});

test("a failed restore keeps no username", async t => {
    const failing = credentialsEnvironment(t, { pending: { username: "x" }, failing: true });
    await failing.credentials.restoreUsernameFromPreviousStep();
    assert.equal(failing.credentials.resolveUsername(""), "");
});

test("an unlabelled change form's new password is the value typed twice", t => {
    const env = credentialsEnvironment(t);
    const form = env.dom.document.body.appendChild(env.dom.document.createElement("form"));
    // Labels such as "Verify" or names such as password1/password2 are not
    // recognised as new-password fields; the repeated value still is.
    const current = env.field(form, "password", { name: "password0" }, "old-secret");
    const fresh = env.field(form, "password", { name: "password1" }, "new-secret");
    env.field(form, "password", { name: "password2", placeholder: "Verify" }, "new-secret");
    const found = env.credentials.findLoginCredentials(form);
    assert.equal(found.password, "new-secret");
    assert.equal(found.passwordField, fresh);
    assert.equal(found.newPassword, true);

    // A mistyped confirmation has no repeated value: fall back to the current
    // password, which the vault already holds, so nothing wrong is saved.
    fresh.value = "new-secreX";
    const mismatch = env.credentials.findLoginCredentials(form);
    assert.equal(mismatch.passwordField, current);
    assert.equal(mismatch.newPassword, false);

    // A single sign-in password is not a new password.
    const login = env.dom.document.body.appendChild(env.dom.document.createElement("form"));
    env.field(login, "password", { name: "pw" }, "only-secret");
    assert.equal(env.credentials.findLoginCredentials(login).newPassword, false);
});
