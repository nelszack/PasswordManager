const test = require("node:test");
const assert = require("node:assert/strict");
const { loadScript } = require("./test_harness.cjs");
const { createDocument } = require("./test_dom.cjs");

const future = () => Math.floor(Date.now() / 1000) + 300;
function request(fields = {}) {
    return {
        entryId: 1,
        entryName: "Work",
        id: "request-one",
        fingerprint: "a".repeat(128),
        application: "Example VPN",
        username: "alice",
        location: "Example City",
        summary: "Login",
        expires_at: future(),
        code_digits: null,
        unsupported: null,
        ...fields,
    };
}

function duoPrompt({ search = "?token=duo-token", responses = {} } = {}) {
    const document = createDocument();
    const elements = {};
    for (const id of ["requests", "status", "destination", "cancel"]) {
        elements[id] = document.body.appendChild(document.createElement(id === "cancel" ? "button" : "div"));
    }
    document.getElementById = id => elements[id];
    const messages = [];
    const timers = new Map();
    let nextTimer = 0;
    const state = { closed: false, runtimeListener: null, pagehide: null, responses };
    const context = {
        document,
        location: { search },
        URLSearchParams,
        RegExp,
        Date,
        JSON,
        Error,
        Promise,
        setTimeout(callback, delay) {
            const id = ++nextTimer;
            timers.set(id, { callback, delay });
            return id;
        },
        clearTimeout: id => timers.delete(id),
        window: {
            close() {
                state.closed = true;
            },
            addEventListener(type, listener) {
                assert.equal(type, "pagehide");
                state.pagehide = listener;
            },
        },
        chrome: {
            runtime: {
                onMessage: {
                    addListener(listener) {
                        state.runtimeListener = listener;
                    },
                },
            },
        },
        PasswordManagerUiTransport: {
            async request(message, fallback) {
                messages.push(message);
                const response =
                    typeof state.responses[message.action] === "function"
                        ? await state.responses[message.action](message)
                        : state.responses[message.action];
                if (!response?.success) throw new Error(response?.error || fallback);
                return response;
            },
        },
    };
    loadScript("duo_prompt.js", context);
    const settle = () => new Promise(resolve => setImmediate(resolve));
    return {
        elements,
        messages,
        timers,
        state,
        settle,
        cards: () => elements.requests.children,
        button: (card, name) => card.querySelectorAll("button").find(button => button.textContent === name),
        codeInput: card => card.querySelectorAll("input")[0],
        async tick() {
            const [id, { callback }] = timers.entries().next().value;
            timers.delete(id);
            await callback();
            await settle();
        },
    };
}

const data = requests => ({
    success: true,
    sourceOrigin: "https://login.example",
    origin: "https://api-test.duosecurity.com",
    requests,
});

test("the Duo window renders request details and refreshes only changed requests", async () => {
    let requests = [request()];
    const env = duoPrompt({ responses: { getDuoPromptData: () => data(requests) } });
    await env.settle();
    assert.equal(
        env.elements.destination.textContent,
        "Login page: https://login.example · Duo: https://api-test.duosecurity.com"
    );
    assert.equal(env.cards().length, 1);
    const card = env.cards()[0];
    assert.equal(card.children[0].textContent, "Work");
    assert.ok(card.children.some(child => child.textContent === "Account: alice"));
    assert.equal(env.elements.status.textContent, "Review this login, then approve or deny.");
    assert.equal([...env.timers.values()][0].delay, 5000);
    await env.tick();
    assert.equal(env.cards()[0], card, "an unchanged request keeps its card and any typed code");
    requests = [];
    await env.tick();
    assert.equal(env.cards().length, 0);
    assert.equal(env.elements.status.textContent, "No pending requests.");
});

test("Verified Push requires the page code before approving; denial sends no code", async () => {
    let decided;
    const env = duoPrompt({
        responses: {
            getDuoPromptData: () => data([request({ code_digits: 3 })]),
            completeDuoPrompt: message => {
                decided = message;
                return { success: true, remaining: 0 };
            },
        },
    });
    await env.settle();
    const card = env.cards()[0];
    const code = env.codeInput(card);
    assert.equal(code.type, "password");
    assert.equal(code.maxLength, 3);
    env.button(card, "Approve").click({ isTrusted: false });
    code.value = "12";
    env.button(card, "Approve").click();
    await env.settle();
    assert.equal(decided, undefined);
    assert.equal(env.elements.status.textContent, "Enter the verification code shown on the login page.");
    code.value = "012";
    env.button(card, "Approve").click();
    await env.settle();
    assert.equal(decided.approve, true);
    assert.equal(decided.verificationCode, "012");
    assert.equal(decided.requestId, "request-one");
    assert.equal(code.value, "", "codes are cleared once sent");
    assert.equal(env.state.closed, true, "the window closes when nothing remains");
});

test("remaining requests reload after a decision, and expired requests are checked again", async () => {
    let requests = [request(), request({ id: "request-two", fingerprint: "b".repeat(128), entryName: "" })];
    const env = duoPrompt({
        responses: {
            getDuoPromptData: () => data(requests),
            completeDuoPrompt: message => {
                requests = requests.filter(r => r.id !== message.requestId);
                return { success: true, remaining: requests.length };
            },
        },
    });
    await env.settle();
    assert.equal(env.cards()[1].children[0].textContent, "Duo login");
    env.button(env.cards()[0], "Deny").click();
    await env.settle();
    assert.equal(env.messages.at(-2).approve, false);
    assert.equal(env.messages.at(-2).verificationCode, "");
    assert.equal(env.cards().length, 1);
    assert.equal(env.state.closed, false);

    requests = [request({ id: "request-three", fingerprint: "c".repeat(128), expires_at: 1 })];
    await env.tick();
    const before = env.messages.length;
    env.button(env.cards()[0], "Deny").click();
    await env.settle();
    assert.equal(env.messages[before].action, "getDuoPromptData", "an expired request is reloaded, not answered");
});

test("unsupported requests can only be denied", async () => {
    const env = duoPrompt({
        responses: { getDuoPromptData: () => data([request({ unsupported: "Requires proximity" })]) },
    });
    await env.settle();
    const card = env.cards()[0];
    assert.equal(env.button(card, "Approve").disabled, true);
    assert.ok(card.children.some(child => child.textContent === "Approval unavailable: Requires proximity"));
});

test("decision failures stop the window and clear its controls", async () => {
    const env = duoPrompt({
        responses: {
            getDuoPromptData: () => data([request()]),
            completeDuoPrompt: { success: false, error: "Duo decision timed out. Check the login before retrying." },
        },
    });
    await env.settle();
    env.button(env.cards()[0], "Approve").click();
    await env.settle();
    assert.equal(env.cards().length, 0);
    assert.match(env.elements.status.textContent, /Check the login before retrying/);
    assert.equal(env.timers.size, 0, "a stopped window never polls again");
});

test("cancelling, locking and leaving stop the window", async () => {
    const cancelled = duoPrompt({
        responses: { getDuoPromptData: () => data([request()]), completeDuoPrompt: { success: true } },
    });
    await cancelled.settle();
    cancelled.elements.cancel.click({ isTrusted: false });
    assert.equal(cancelled.state.closed, false);
    await cancelled.elements.cancel.listeners.get("click")[0]({ isTrusted: true });
    assert.equal(cancelled.messages.at(-1).cancel, true);
    assert.equal(cancelled.state.closed, true);

    const failedCancel = duoPrompt({ responses: { getDuoPromptData: () => data([request()]) } });
    await failedCancel.settle();
    await failedCancel.elements.cancel.listeners.get("click")[0]({ isTrusted: true });
    assert.equal(failedCancel.elements.status.textContent, "Duo window unavailable");

    const locked = duoPrompt({ responses: { getDuoPromptData: () => data([request()]) } });
    await locked.settle();
    locked.state.runtimeListener({ action: "statusChanged", status: { native: true, running: true, locked: false } });
    assert.equal(locked.state.closed, false);
    locked.state.runtimeListener({ action: "statusChanged", status: { native: true, running: true, locked: true } });
    assert.equal(locked.state.closed, true);
    assert.equal(locked.elements.status.textContent, "Vault locked or disconnected");

    const left = duoPrompt({ responses: { getDuoPromptData: () => data([request()]) } });
    await left.settle();
    left.state.pagehide();
    assert.equal(left.timers.size, 0);
});

test("missing tokens and unavailable data show an error without polling", async () => {
    const missing = duoPrompt({ search: "" });
    await missing.settle();
    assert.equal(missing.elements.status.textContent, "Missing Duo window token");
    assert.equal(missing.messages.length, 0);
    const expired = duoPrompt({ responses: { getDuoPromptData: { success: false, error: "Duo window expired" } } });
    await expired.settle();
    assert.equal(expired.elements.status.textContent, "Duo window expired");
    assert.equal(expired.timers.size, 0);
});
