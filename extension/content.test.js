const test = require("node:test");
const assert = require("node:assert/strict");
const { installDom } = require("./test_dom.cjs");

// Runs the real content modules against the fake DOM with controllable time.
async function contentEnvironment(t) {
    const clock = { now: 1_000_000, timers: [] };
    t.mock.method(Date, "now", () => clock.now);
    const messages = [];
    const observers = [];
    const runtimeListeners = new Set();
    const chrome = {
        runtime: {
            id: "extension-id",
            lastError: null,
            sendMessage(message, callback) {
                messages.push(message);
                const responses = {
                    consumePendingCredentials: { success: true, pending: null },
                    openCredentialPrompt: { success: true, skipped: true },
                    setPendingCredentials: { success: true },
                };
                queueMicrotask(() => callback?.(responses[message.action]));
            },
            onMessage: {
                addListener: listener => runtimeListeners.add(listener),
                removeListener: listener => runtimeListeners.delete(listener),
            },
        },
        storage: {
            local: { get: (_keys, callback) => callback({}) },
            onChanged: { addListener() {}, removeListener() {} },
        },
    };
    const location = { href: "https://login.example/signin" };
    const dom = installDom(t, {
        chrome,
        location,
        navigator: { userActivation: { isActive: true } },
        setTimeout(callback, delay = 0) {
            const timer = { callback, at: clock.now + delay };
            clock.timers.push(timer);
            return timer;
        },
        clearTimeout(timer) {
            clock.timers = clock.timers.filter(candidate => candidate !== timer);
        },
        MutationObserver: class {
            constructor(callback) {
                this.callback = callback;
                this.observed = [];
                observers.push(this);
            }
            observe(root, options) {
                this.observed.push({ root, options });
            }
            takeRecords() {
                return [];
            }
            disconnect() {
                this.disconnected = true;
            }
        },
    });
    dom.window.location = location;
    dom.window.top = dom.window;
    const { document } = dom;
    const form = document.createElement("form");
    const username = dom.input("email");
    username.autocomplete = "username";
    const password = dom.input("password");
    password.autocomplete = "current-password";
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.setAttribute("aria-label", "Show password");
    const next = document.createElement("button");
    next.type = "button";
    next.textContent = "Next";
    const submit = document.createElement("button");
    submit.textContent = "Sign in";
    form.append(username, password, toggle, next, submit);
    document.body.appendChild(form);
    const outside = document.createElement("button");
    outside.textContent = "Continue";
    document.body.appendChild(outside);

    const content = require("./content.js");
    const controller = content.create();
    dom.cleanup(() => controller.dispose());
    await controller.start();
    const settle = async () => {
        for (let i = 0; i < 5; i++) await Promise.resolve();
    };
    return {
        chrome,
        clock,
        content,
        controller,
        document,
        dom,
        form,
        messages,
        observers,
        outside,
        next,
        password,
        submit,
        toggle,
        username,
        settle,
        prompts: () => messages.filter(message => message.action === "openCredentialPrompt"),
        type(input, value) {
            input.value = value;
            document.dispatch("input", { target: input, composedPath: () => [input] });
        },
        click(element, event = {}) {
            document.dispatch("click", { target: element, composedPath: () => [element], ...event });
        },
        async advance(ms) {
            const until = clock.now + ms;
            for (;;) {
                await settle();
                clock.timers.sort((a, b) => a.at - b.at);
                if (!clock.timers.length || clock.timers[0].at > until) break;
                const timer = clock.timers.shift();
                clock.now = Math.max(clock.now, timer.at);
                timer.callback();
            }
            clock.now = until;
            await settle();
        },
        pagehide(isTrusted = true) {
            controller.handlePageHide({ type: "pagehide", isTrusted });
        },
    };
}

test("a show-password toggle never opens the save prompt, so the real submit still does", async t => {
    const env = await contentEnvironment(t);
    env.type(env.username, "alice@example.com");
    env.type(env.password, "half-typ");
    env.click(env.toggle);
    await env.advance(1000);
    assert.equal(env.prompts().length, 0);
    env.type(env.password, "half-typed-and-finished");
    env.click(env.submit);
    await env.settle();
    assert.deepEqual(
        env.prompts().map(({ username, password }) => ({ username, password })),
        [{ username: "alice@example.com", password: "half-typed-and-finished" }]
    );
});

test("other buttons prompt only once the page leaves the password step", async t => {
    for (const scenario of ["unchanged", "type toggled", "removed", "cleared", "hidden", "swapped for a text copy"]) {
        await t.test(scenario, async t => {
            const env = await contentEnvironment(t);
            env.type(env.username, "alice@example.com");
            env.type(env.password, "secret");
            env.click(env.next);
            await env.settle();
            assert.equal(env.prompts().length, 0, "nothing opens at click time");
            if (scenario === "type toggled") env.password.type = "text";
            if (scenario === "removed") env.password.remove();
            if (scenario === "cleared") env.password.value = "";
            if (scenario === "hidden") env.password.hiddenForTest = true;
            if (scenario === "swapped for a text copy") {
                const copy = env.dom.input("text");
                copy.value = "secret";
                env.password.insertAdjacentElement("afterend", copy);
                env.password.remove();
            }
            await env.advance(1000);
            const expected = ["removed", "cleared", "hidden"].includes(scenario) ? 1 : 0;
            assert.equal(env.prompts().length, expected);
            // The snapshot was captured before the page's handler changed the field.
            if (expected) assert.equal(env.prompts()[0].password, "secret");
        });
    }
});

test("Enter in a credential field prompts at once", async t => {
    const env = await contentEnvironment(t);
    env.type(env.username, "alice@example.com");
    env.type(env.password, "secret");
    env.document.dispatch("keydown", {
        key: "Enter",
        target: env.password,
        composedPath: () => [env.password],
    });
    await env.settle();
    assert.equal(env.prompts().length, 1);
    const remembered = env.messages.filter(message => message.action === "setPendingCredentials");
    assert.equal(remembered.at(-1).pending.username, "alice@example.com");
});

test("buttons outside the password's form prompt only once the page leaves the password step", async t => {
    for (const scenario of ["unrelated banner button", "form-less login continue"]) {
        await t.test(scenario, async t => {
            const env = await contentEnvironment(t);
            env.type(env.username, "alice@example.com");
            env.type(env.password, "secret");
            env.click(env.outside);
            await env.settle();
            assert.equal(env.prompts().length, 0, "nothing opens at click time");
            if (scenario === "form-less login continue") env.password.remove();
            await env.advance(1000);
            const expected = scenario === "form-less login continue" ? 1 : 0;
            assert.equal(env.prompts().length, expected);
            const remembered = env.messages.filter(message => message.action === "setPendingCredentials");
            assert.equal(remembered.at(-1).pending.username, "alice@example.com");
        });
    }
});

test("untrusted, composing, extension-owned and non-credential events are ignored", async t => {
    const env = await contentEnvironment(t);
    env.type(env.username, "alice@example.com");
    env.type(env.password, "secret");
    env.click(env.submit, { isTrusted: false });
    env.document.dispatch("keydown", {
        key: "Enter",
        isComposing: true,
        target: env.password,
        composedPath: () => [env.password],
    });
    env.document.dispatch("keydown", { key: "a", target: env.password, composedPath: () => [env.password] });
    const host = env.username.nextElementSibling;
    assert.equal(host.localName, "pm-field-control", "discovery attached a control beside the username");
    env.click(host);
    env.click(env.form);
    await env.advance(1000);
    assert.equal(env.prompts().length, 0);
});

test("leaving the page confirms a pending click with the credentials it captured", async t => {
    const env = await contentEnvironment(t);
    env.type(env.username, "alice@example.com");
    env.type(env.password, "secret");
    env.click(env.next);
    // A scripted sign-in clears the field and navigates before the confirmation poll.
    env.password.value = "";
    env.pagehide(false);
    assert.equal(env.prompts().length, 0, "page scripts cannot dispatch a page hide");
    env.pagehide();
    assert.deepEqual(
        env.prompts().map(({ username, password }) => ({ username, password })),
        [{ username: "alice@example.com", password: "secret" }]
    );
    await env.advance(1000);
    assert.equal(env.prompts().length, 1, "the confirmation poll does not prompt again");
});

test("leaving the page captures logins that navigate without a click on a control", async t => {
    const env = await contentEnvironment(t);
    env.type(env.username, "alice@example.com");
    env.type(env.password, "secret");
    // A <div> "Sign in" or a script redirect.
    env.pagehide();
    assert.equal(env.prompts().length, 1);
    assert.equal(env.prompts()[0].username, "alice@example.com");
    env.pagehide();
    assert.equal(env.prompts().length, 1, "one prompt per document");
});

test("leaving a username step remembers the username without prompting", async t => {
    const env = await contentEnvironment(t);
    env.password.remove();
    env.type(env.username, "alice@example.com");
    env.pagehide();
    assert.equal(env.prompts().length, 0);
    assert.equal(env.messages.at(-1).action, "setPendingCredentials");
    assert.equal(env.messages.at(-1).pending.username, "alice@example.com");
});

test("pages without credential input never prompt on page hide", async t => {
    const env = await contentEnvironment(t);
    env.password.value = "prefilled-by-page";
    env.pagehide();
    assert.equal(env.prompts().length, 0);
});

test("an invalidated extension context disposes the controller at its next event", async t => {
    const env = await contentEnvironment(t);
    assert.equal(env.content.runtimeAvailable(), true);
    env.type(env.username, "alice@example.com");
    env.type(env.password, "secret");
    delete env.chrome.runtime.id;
    assert.equal(env.content.runtimeAvailable(), false);
    env.click(env.submit);
    await env.settle();
    assert.equal(env.prompts().length, 0);
    assert.equal(
        env.observers.every(observer => observer.disconnected),
        true,
        "observers stop"
    );
    assert.equal(env.username.nextElementSibling, env.password, "in-page controls are removed");
    env.chrome.runtime.id = "extension-id";
    env.click(env.submit);
    env.pagehide();
    await env.settle();
    assert.equal(env.prompts().length, 0, "a disposed controller stays inert");

    Object.defineProperty(env.chrome, "runtime", {
        get() {
            throw new Error("Extension context invalidated.");
        },
    });
    assert.equal(env.content.runtimeAvailable(), false);
});

test("discovered roots stop listening after disposal", async t => {
    const env = await contentEnvironment(t);
    assert.deepEqual(env.controller.roots(), [env.document]);
    const observed = env.observers.flatMap(observer => observer.observed);
    assert.equal(observed[0].options.characterData, true, "the top frame also watches text for Duo");
    env.controller.dispose();
    env.controller.dispose();
    assert.deepEqual(env.controller.roots(), [], "disposal releases every root's listeners");
    env.type(env.username, "alice@example.com");
    env.type(env.password, "secret");
    env.click(env.submit);
    await env.settle();
    assert.equal(env.prompts().length, 0);
});
