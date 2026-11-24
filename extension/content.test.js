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
          claimPopupFill: chrome.claimPopupFill || {
            success: true,
            payload: { username: "alice@example.com", password: "synthetic-secret" },
          },
        };
        queueMicrotask(() => callback?.(responses[message.action]));
      },
      onMessage: {
        addListener: (listener) => runtimeListeners.add(listener),
        removeListener: (listener) => runtimeListeners.delete(listener),
      },
      _listeners: runtimeListeners,
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
      clock.timers = clock.timers.filter((candidate) => candidate !== timer);
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
    prompts: () =>
      messages.filter((message) => message.action === "openCredentialPrompt"),
    remembered: () =>
      messages.filter((message) => message.action === "setPendingCredentials"),
    // Delivers a runtime message to every listener; "ignored" when none answers.
    ask(message, sender = { id: "extension-id" }) {
      return new Promise((resolve) => {
        let answered = false;
        for (const listener of runtimeListeners) {
          if (listener(message, sender, resolve) === true) answered = true;
        }
        if (!answered) resolve("ignored");
      });
    },
    type(input, value) {
      input.value = value;
      document.dispatch("input", {
        target: input,
        composedPath: () => [input],
      });
    },
    press(input, key = "Enter", event = {}) {
      document.dispatch("keydown", {
        key,
        target: input,
        composedPath: () => [input],
        ...event,
      });
    },
    click(element, event = {}) {
      document.dispatch("click", {
        target: element,
        composedPath: () => [element],
        ...event,
      });
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

test("a show-password toggle never opens the save prompt, so the real submit still does", async (t) => {
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
    [{ username: "alice@example.com", password: "half-typed-and-finished" }],
  );
});

test("other buttons prompt only once the page leaves the password step", async (t) => {
  for (const scenario of [
    "unchanged",
    "type toggled",
    "removed",
    "removed after a slow sign-in request",
    "cleared",
    "hidden",
    "swapped for a text copy",
  ]) {
    await t.test(scenario, async (t) => {
      const env = await contentEnvironment(t);
      env.type(env.username, "alice@example.com");
      env.type(env.password, "secret");
      env.click(env.next);
      await env.settle();
      assert.equal(env.prompts().length, 0, "nothing opens at click time");
      if (scenario === "type toggled") env.password.type = "text";
      if (scenario === "removed") env.password.remove();
      if (scenario === "removed after a slow sign-in request") {
        await env.advance(1500);
        env.password.remove();
      }
      if (scenario === "cleared") env.password.value = "";
      if (scenario === "hidden") env.password.hiddenForTest = true;
      if (scenario === "swapped for a text copy") {
        const copy = env.dom.input("text");
        copy.value = "secret";
        env.password.insertAdjacentElement("afterend", copy);
        env.password.remove();
      }
      await env.advance(1000);
      const expected = ["unchanged", "type toggled", "swapped for a text copy"].includes(scenario)
        ? 0
        : 1;
      assert.equal(env.prompts().length, expected);
      // The snapshot was captured before the page's handler changed the field.
      if (expected) assert.equal(env.prompts()[0].password, "secret");
    });
  }
});

test("buttons outside the password's form prompt only once the page leaves the password step", async (t) => {
  for (const scenario of [
    "unrelated banner button",
    "form-less login continue",
  ]) {
    await t.test(scenario, async (t) => {
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
      assert.equal(env.remembered().at(-1).pending.username, "alice@example.com");
    });
  }
});

test("only real submit controls prompt at once", async (t) => {
  for (const [scenario, make, immediate] of [
    [
      "image input in the form",
      (env) => Object.assign(env.dom.input("image"), {}),
      true,
    ],
    [
      "explicit submit outside a form",
      (env) => {
        const button = env.document.createElement("button");
        button.setAttribute("type", "submit");
        return button;
      },
      true,
    ],
    [
      "scripted role=button",
      (env) => {
        const div = env.document.createElement("div");
        div.setAttribute("role", "button");
        return div;
      },
      false,
    ],
  ]) {
    await t.test(scenario, async (t) => {
      const env = await contentEnvironment(t);
      const control = make(env);
      if (scenario === "explicit submit outside a form")
        env.document.body.appendChild(control);
      else env.form.appendChild(control);
      env.type(env.username, "alice@example.com");
      env.type(env.password, "secret");
      env.click(control);
      await env.settle();
      assert.equal(env.prompts().length, immediate ? 1 : 0);
    });
  }
});

test("untrusted, composing, extension-owned and non-credential events are ignored", async (t) => {
  const env = await contentEnvironment(t);
  env.type(env.username, "alice@example.com");
  env.type(env.password, "secret");
  env.click(env.submit, { isTrusted: false });
  env.press(env.password, "Enter", { isComposing: true });
  env.press(env.password, "a");
  const host = env.username.nextElementSibling;
  assert.equal(
    host.localName,
    "pm-field-control",
    "discovery attached a control beside the username",
  );
  env.click(host);
  env.click(env.form);
  await env.advance(1000);
  assert.equal(env.prompts().length, 0);
});

test("leaving the page confirms a pending click with the credentials it captured", async (t) => {
  const env = await contentEnvironment(t);
  env.type(env.username, "alice@example.com");
  env.type(env.password, "secret");
  env.click(env.next);
  // A scripted sign-in clears the field and navigates before the confirmation poll.
  env.password.value = "";
  env.pagehide(false);
  assert.equal(
    env.prompts().length,
    0,
    "page scripts cannot dispatch a page hide",
  );
  env.pagehide();
  assert.deepEqual(
    env.prompts().map(({ username, password }) => ({ username, password })),
    [{ username: "alice@example.com", password: "secret" }],
  );
  await env.advance(1000);
  assert.equal(
    env.prompts().length,
    1,
    "the confirmation poll does not prompt again",
  );
});

test("leaving the page captures logins that navigate without a click on a control", async (t) => {
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

test("leaving a username step remembers the username without prompting", async (t) => {
  const env = await contentEnvironment(t);
  env.password.remove();
  env.type(env.username, "alice@example.com");
  env.pagehide();
  assert.equal(env.prompts().length, 0);
  assert.equal(env.messages.at(-1).action, "setPendingCredentials");
  assert.equal(env.messages.at(-1).pending.username, "alice@example.com");
});

test("pages without credential input never prompt on page hide", async (t) => {
  const env = await contentEnvironment(t);
  env.password.value = "prefilled-by-page";
  env.pagehide();
  assert.equal(env.prompts().length, 0);
});

test("an invalidated extension context disposes the controller at its next event", async (t) => {
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
    env.observers.every((observer) => observer.disconnected),
    true,
    "observers stop",
  );
  assert.equal(
    env.username.nextElementSibling,
    env.password,
    "in-page controls are removed",
  );
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

test("discovered roots stop listening after disposal", async (t) => {
  const env = await contentEnvironment(t);
  assert.deepEqual(env.controller.roots(), [env.document]);
  const observed = env.observers.flatMap((observer) => observer.observed);
  assert.equal(
    observed[0].options.characterData,
    true,
    "the top frame also watches text for Duo",
  );
  env.controller.dispose();
  env.controller.dispose();
  assert.deepEqual(
    env.controller.roots(),
    [],
    "disposal releases every root's listeners",
  );
  env.type(env.username, "alice@example.com");
  env.type(env.password, "secret");
  env.click(env.submit);
  await env.settle();
  assert.equal(env.prompts().length, 0);
});

test("the fill shortcut opens the login picker only from the extension in the focused frame", async (t) => {
  const env = await contentEnvironment(t);
  let focused = true;
  env.document.hasFocus = () => focused;
  const deliver = (message, sender) => {
    for (const listener of env.chrome.runtime._listeners) listener(message, sender);
  };
  const pickerRequests = () => env.messages.filter((message) => message.action === "openSecurePicker");
  env.dom.flushFrames();
  deliver({ action: "pmShortcutFill" }, { id: "other-extension" });
  deliver({ action: "somethingElse" }, { id: "extension-id" });
  focused = false;
  deliver({ action: "pmShortcutFill" }, { id: "extension-id" });
  await env.settle();
  assert.equal(pickerRequests().length, 0);
  focused = true;
  env.username.focus();
  deliver({ action: "pmShortcutFill" }, { id: "extension-id" });
  await env.settle();
  assert.equal(pickerRequests().length, 1);
  assert.equal(pickerRequests()[0].kind, "login");
  env.controller.dispose();
  assert.equal(env.chrome.runtime._listeners.size, 0, "dispose removes every runtime listener");
});

test("the toolbar popup fills the top frame's login form only through a claimed token", async (t) => {
  const env = await contentEnvironment(t);
  env.dom.flushFrames();
  const { ask } = env;
  assert.equal(await ask({ action: "pmPopupFill", token: "t" }, { id: "other-extension" }), "ignored");
  assert.equal(await ask({ action: "pmPopupFill", token: 5 }), "ignored");
  const filled = await ask({ action: "pmPopupFill", token: "t" });
  assert.equal(filled.success, true, filled.error);
  await env.settle();
  assert.equal(env.username.value, "alice@example.com");
  assert.equal(env.password.value, "synthetic-secret");
  assert.equal(env.messages.at(-1).action, "claimPopupFill");
  assert.equal(env.messages.filter((message) => message.action === "openSecurePicker").length, 0);

  env.chrome.claimPopupFill = { success: false, error: "Fill request expired" };
  const expired = await ask({ action: "pmPopupFill", token: "t" });
  assert.deepEqual({ ...expired }, { success: false, error: "Fill request expired" });

  env.dom.window.top = {};
  assert.equal(await ask({ action: "pmPopupFill", token: "t" }), "ignored", "embedded frames never fill");
  env.dom.window.top = env.dom.window;
  env.controller.dispose();
  assert.equal(await ask({ action: "pmPopupFill", token: "t" }), "ignored", "a disposed page stays inert");
});

// A settings page's change-password form: current, new and confirm fields and
// a scripted "Save" button. The page saves in the background and stays put.
function changePasswordForm(env, { current = true } = {}) {
  const form = env.document.createElement("form");
  const fields = [];
  if (current) {
    const old = env.dom.input("password");
    old.autocomplete = "current-password";
    fields.push(old);
  }
  const next = env.dom.input("password");
  next.autocomplete = "new-password";
  const confirm = env.dom.input("password");
  confirm.autocomplete = "new-password";
  confirm.name = "confirmPassword";
  const save = env.document.createElement("button");
  save.type = "button";
  save.textContent = "Change password";
  form.append(...fields, next, confirm, save);
  env.form.remove();
  env.document.body.appendChild(form);
  return { old: fields[0], next, confirm, save };
}

test("a change-password save button prompts at once with the new password", async (t) => {
  for (const current of [true, false]) {
    await t.test(current ? "with current password" : "reset form", async (t) => {
      const env = await contentEnvironment(t);
      const form = changePasswordForm(env, { current });
      if (current) env.type(form.old, "old-secret");
      env.type(form.next, "new-secret");
      env.type(form.confirm, "new-secret");
      env.click(form.save);
      await env.settle();
      assert.deepEqual(
        env.prompts().map(({ password }) => password),
        ["new-secret"],
      );
    });
  }
});

test("a change-password form with a mismatched confirmation never prompts", async (t) => {
  const env = await contentEnvironment(t);
  const form = changePasswordForm(env);
  env.type(form.old, "old-secret");
  env.type(form.next, "new-secret");
  env.type(form.confirm, "new-secre");
  env.click(form.save);
  env.press(form.confirm);
  await env.advance(5000);
  assert.equal(env.prompts().length, 0);
  // Fixing the typo and saving again still prompts.
  env.type(form.confirm, "new-secret");
  env.click(form.save);
  await env.settle();
  assert.equal(env.prompts().length, 1);
});

test("Enter in a credential field prompts at once", async (t) => {
  await t.test("sign-in password", async (t) => {
    const env = await contentEnvironment(t);
    env.type(env.username, "alice@example.com");
    env.type(env.password, "secret");
    env.press(env.password);
    await env.settle();
    assert.deepEqual(env.prompts().map(({ password }) => password), ["secret"]);
    assert.equal(env.remembered().at(-1).pending.username, "alice@example.com");
  });
  await t.test("new-password confirmation", async (t) => {
    const env = await contentEnvironment(t);
    const form = changePasswordForm(env, { current: false });
    env.type(form.next, "new-secret");
    env.type(form.confirm, "new-secret");
    env.press(form.confirm);
    await env.settle();
    assert.deepEqual(env.prompts().map(({ password }) => password), ["new-secret"]);
  });
});

test("the toolbar popup fills a same-origin embedded frame only when asked for embedded frames", async (t) => {
  const env = await contentEnvironment(t);
  env.dom.flushFrames();
  env.dom.window.location.origin = "https://login.example";
  env.dom.window.top = {};
  const { ask } = env;
  assert.equal(await ask({ action: "pmPopupFill", token: "t" }), "ignored", "first ask goes to the top frame");
  assert.equal(
    await ask({ action: "pmPopupFill", token: "t", embedded: true, origin: "https://other.example" }),
    "ignored",
    "frames of other origins stay silent",
  );
  const filled = await ask({ action: "pmPopupFill", token: "t", embedded: true, origin: "https://login.example" });
  assert.equal(filled.success, true, filled.error);
  await env.settle();
  assert.equal(env.password.value, "synthetic-secret");

  // Another frame claimed it first: this frame neither fills nor answers.
  env.password.value = "";
  env.chrome.claimPopupFill = { success: false, duplicate: true, error: "Already filled" };
  const silent = await Promise.race([
    ask({ action: "pmPopupFill", token: "t", embedded: true, origin: "https://login.example" }),
    env.settle().then(() => "silent"),
  ]);
  assert.equal(silent, "silent");
  assert.equal(env.password.value, "");
});

test("a top frame without a login form says so for the embedded-frame fallback", async (t) => {
  const env = await contentEnvironment(t);
  env.form.remove();
  env.dom.flushFrames();
  const answer = await env.ask({ action: "pmPopupFill", token: "t" });
  assert.equal(answer.noForm, true);
  assert.match(answer.error, /No sign-in form/);
});
