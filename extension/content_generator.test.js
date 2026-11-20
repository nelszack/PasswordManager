const test = require("node:test");
const assert = require("node:assert/strict");
const { installDom } = require("./test_dom.cjs");

function generatorEnvironment(t, stored = {}) {
    const reads = [];
    const changeListeners = new Set();
    let pendingRead = null;
    const timers = [];
    const dom = installDom(t, {
        location: { href: "https://signup.example/register" },
        setTimeout: callback => timers.push(callback),
        chrome: {
            storage: {
                local: {
                    get(keys, callback) {
                        reads.push(keys);
                        pendingRead = () => callback(stored);
                    },
                },
                onChanged: {
                    addListener: listener => changeListeners.add(listener),
                    removeListener: listener => changeListeners.delete(listener),
                },
            },
        },
    });
    const filled = [];
    const credentials = { lastInput: null };
    const controlsModule = require("./content_controls.js");
    const controls = controlsModule.create({ bridge: {}, credentials: {}, autofill: {} });
    const generator = require("./content_generator.js").create({
        controls,
        bridge: {
            fillInput(input, value) {
                input.value = value;
                filled.push(input);
            },
        },
        credentials,
    });
    dom.cleanup(() => {
        generator.dispose();
        controls.dispose();
    });
    const form = dom.document.createElement("form");
    dom.document.body.appendChild(form);
    const field = (type, attributes = {}) => {
        const input = dom.input(type);
        for (const [name, value] of Object.entries(attributes)) {
            if (name === "autocomplete") input.autocomplete = value;
            else input.setAttribute(name, value);
        }
        form.appendChild(input);
        return input;
    };
    return {
        dom,
        form,
        field,
        filled,
        reads,
        timers,
        credentials,
        generator,
        changeListeners,
        finishRead: () => pendingRead(),
        button: input => input.nextElementSibling.attachedShadow.querySelectorAll("button")[0],
    };
}

test("generated passwords fill only new-password inputs, never a confirm-email field", t => {
    const env = generatorEnvironment(t);
    const email = env.field("email", { autocomplete: "email", placeholder: "Email" });
    const confirmEmail = env.field("email", { placeholder: "Confirm email" });
    const password = env.field("password", { autocomplete: "new-password" });
    const confirmPassword = env.field("password", { placeholder: "Confirm password" });
    env.generator.createGeneratorButton(password);
    env.finishRead();
    env.button(password).click();
    assert.deepEqual(env.filled, [password, confirmPassword]);
    assert.equal(confirmEmail.value, "");
    assert.equal(email.value, "");
    assert.equal(password.value.length, 20);
    assert.equal(confirmPassword.value, password.value);
    assert.equal(env.credentials.lastInput, password);
    assert.equal(env.dom.document.activeElement, password);
});

test("the generator falls back to its own field and confirms the fill accessibly", t => {
    const env = generatorEnvironment(t);
    const password = env.field("password");
    env.generator.createGeneratorButton(password);
    const button = env.button(password);
    button.click({ isTrusted: false });
    assert.deepEqual(env.filled, []);
    button.click();
    assert.deepEqual(env.filled, [password]);
    assert.equal(button.dataset.icon, "check");
    const toast = env.dom.document.body.children.at(-1);
    assert.equal(toast.localName, "pm-field-control");
    assert.equal(toast.attachedShadow.querySelectorAll("div")[0].getAttribute("role"), "status");
    assert.equal(toast.style.top, "46px");
    for (const timer of env.timers.splice(0)) timer();
    assert.equal(button.dataset.icon, "sparkle");
    assert.equal(toast.isConnected, false);
});

test("site settings are read only once a generator is shown and follow later changes", t => {
    const env = generatorEnvironment(t, { pmGenerator: { length: 32 } });
    assert.deepEqual(env.reads, [], "frames without a generator never touch extension storage");
    assert.equal(env.changeListeners.size, 0);
    const password = env.field("password");
    env.generator.createGeneratorButton(password);
    env.generator.createGeneratorButton(password);
    assert.equal(env.reads.length, 1);
    assert.equal(env.form.children.length, 2, "one control per field");
    // A change reported while the read is pending is newer than the read result.
    for (const listener of env.changeListeners) {
        listener({ pmGenerator: { newValue: { length: 24 } } }, "local");
        listener({ pmGenerator: { newValue: { length: 99 } } }, "sync");
    }
    env.finishRead();
    env.button(password).click();
    assert.equal(password.value.length, 24);
    for (const listener of env.changeListeners) listener({ pmGenerator: { newValue: { length: 16 } } }, "local");
    env.button(password).click();
    assert.equal(password.value.length, 16);
    env.generator.removeGeneratorButton(password);
    assert.equal(env.form.children.length, 1);
    env.generator.dispose();
    assert.equal(env.changeListeners.size, 0);
});
