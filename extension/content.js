"use strict";
const detection = require("./content_detection.js");
const PasswordManagerFormSubmission = require("./form_submission.js");
const bridgeModule = require("./content_bridge.js");
const credentialsModule = require("./content_credentials.js");
const autofillModule = require("./content_autofill.js");
const controlsModule = require("./content_controls.js");
const generatorModule = require("./content_generator.js");
const observerModule = require("./content_observer.js");
const duoModule = require("./content_duo.js");

const ADVANCE_CONTROLS =
  "button, input[type='button'], input[type='submit'], input[type='image'], [role='button']";
// Buttons that commit a new password on change-password and sign-up forms.
const SAVE_PASSWORD_RE =
  /\b(save|change|update|reset|set|submit|confirm|done|apply|create|sign[- ]?up|register)\b/i;

// After an extension update or reload, scripts from the old version keep running
// with a runtime that can no longer deliver messages.
function runtimeAvailable() {
  try {
    return Boolean(chrome.runtime?.id);
  } catch (_) {
    return false;
  }
}
module.exports.runtimeAvailable = runtimeAvailable;

module.exports.create = function create({
  contextValid = runtimeAvailable,
} = {}) {
  const {
    USERNAME_INPUT_TYPES,
    isCredentialInput,
    credentialScope,
    isElementVisible,
    isExtensionUi,
    isNewPasswordInput,
    isUsableInput,
    isVisibilityToggle,
    scopeInputs,
    withVisibilityCache,
  } = detection;
  const rootControllers = new Map();
  const handledEvents = new WeakSet();
  let disposed = false;
  let pendingAdvance = null;
  const bridge = bridgeModule.create({ onInvalidated: () => dispose() });
  const credentials = credentialsModule.create({
    roots: () => rootControllers.keys(),
  });
  const {
    restoreUsernameFromPreviousStep,
    storeUsernameForLater,
    rememberUsernameAcrossNavigation,
    findLoginCredentials,
    usernameFromScope,
    credentialsFromScope,
    resolveUsername,
  } = credentials;
  const { openCredentialPrompt } = bridge;
  const credentialAttempt =
    PasswordManagerFormSubmission.createCredentialAttempt((captured) => {
      if (captured.username)
        rememberUsernameAcrossNavigation(captured.username);
      return openCredentialPrompt(
        resolveUsername(captured.username),
        captured.password,
      );
    });
  function attemptCredentials(captured) {
    return disposed ? Promise.resolve() : credentialAttempt.run(captured);
  }
  let credentialUserIntent = false;
  const autofill = autofillModule.create({ bridge });
  const controls = controlsModule.create({ bridge, credentials, autofill });
  const generator = generatorModule.create({ controls, bridge, credentials });
  // Created before the observer, which dispatches page mutations to it.
  let observer = null;
  let duo = null;
  duo = duoModule.create({ flushMutations: () => observer?.flush(), alive });
  // Its first check can find the extension context already gone.
  if (disposed) duo.dispose();
  observer = observerModule.create({
    controls,
    generator,
    autofill,
    onRoot: registerRoot,
    onRemoveRoot: unregisterRoot,
    observeText: duo.enabled,
    onMutations(mutations) {
      if (!alive()) return;
      duo.mutated();
      if (mutations.some((mutation) => mutation.type !== "characterData"))
        controls.layoutChanged();
    },
  });

  // The extension's keyboard shortcut reaches every frame; only the focused
  // frame acts. Pages cannot send extension runtime messages.
  function deepActiveElement() {
    let active = document.activeElement;
    while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
    return active;
  }
  function shortcutListener(message, sender) {
    if (message?.action !== "pmShortcutFill" || sender?.id !== chrome.runtime.id) return;
    if (!alive() || !document.hasFocus()) return;
    withVisibilityCache(() => controls.activateShortcut(deepActiveElement()));
  }
  chrome.runtime.onMessage.addListener(shortcutListener);

  // The toolbar popup asks the top frame to fill a login it listed for this
  // site. When the top frame has no login form, it asks same-origin embedded
  // frames, since many sites host their sign-in form in an iframe.
  const NO_FORM =
    "No sign-in form was found on this page. Use the key button in the login field instead.";
  function popupFillListener(message, sender, sendResponse) {
    if (message?.action !== "pmPopupFill" || sender?.id !== chrome.runtime.id) return;
    if (!alive() || typeof message.token !== "string") return;
    const embedded = window !== window.top;
    if (embedded !== (message.embedded === true)) return;
    if (embedded && message.origin !== window.location.origin) return;
    const filled = withVisibilityCache(() =>
      controls.fillFromPopup(deepActiveElement(), () =>
        bridge.claimPopupFill(message.token),
      ),
    );
    // An embedded frame without a form, or one that lost the claim to another
    // frame, stays silent so the frame that filled answers.
    if (embedded && filled === false) return;
    Promise.resolve(filled).then(
      (done) => {
        if (done) sendResponse({ success: true });
        else if (!embedded) sendResponse({ success: false, noForm: true, error: NO_FORM });
      },
      (error) =>
        sendResponse({ success: false, error: error?.message || "Could not fill" }),
    );
    return true;
  }
  chrome.runtime.onMessage.addListener(popupFillListener);

  // Dispose instead of acting once the extension context is gone.
  function alive() {
    if (disposed) return false;
    if (contextValid()) return true;
    dispose();
    return false;
  }

  function listen(root, type, handler) {
    root.addEventListener(
      type,
      (event) => {
        if (handledEvents.has(event)) return;
        handledEvents.add(event);
        if (!alive()) return;
        // Each event is one synchronous read phase; share visibility reads.
        withVisibilityCache(() => handler(event));
      },
      { capture: true, signal: rootControllers.get(root).signal },
    );
  }
  function unregisterRoot(root) {
    rootControllers.get(root)?.abort();
    rootControllers.delete(root);
  }

  // Has the page left the password step captured by a non-submit click?
  // Clearing, hiding or removing the password field counts; a show/hide toggle
  // that swaps it for a text copy of the same value does not.
  function leftPasswordStep(snapshot) {
    const { passwordField: field, password, scope } = snapshot;
    if (!field) return false;
    return withVisibilityCache(() => {
      if (field.isConnected && field.value && isElementVisible(field))
        return false;
      const scopeConnected = scope && (scope === document || scope.isConnected);
      return !(
        scopeConnected &&
        scopeInputs(scope).some(
          (input) =>
            input !== field &&
            input.isConnected &&
            input.value === password &&
            isElementVisible(input),
        )
      );
    });
  }

  // Login fields, plus the new-password fields of change-password and sign-up
  // forms, whose values are captured but never autofilled.
  function isCaptureInput(input) {
    return (
      isCredentialInput(input) ||
      (input.type === "password" && isUsableInput(input))
    );
  }

  // Change-password pages often save in the background and stay put, so a
  // "Save"/"Change password" button prompts at once when the new password is
  // complete: every filled new-password field (new and confirm) agrees.
  function savesNewPassword(control, snapshot) {
    const { passwordField: field, password } = snapshot;
    if (!field || !password || !snapshot.newPassword) return false;
    if (!(control instanceof Element) || control instanceof HTMLInputElement)
      return control instanceof HTMLInputElement &&
        ["button", "submit"].includes(control.type) &&
        SAVE_PASSWORD_RE.test(control.value);
    const text = String(control.textContent || "").trim();
    return [
      text.length <= 40 ? text : "",
      control.getAttribute("aria-label"),
      control.getAttribute("title"),
    ].some((value) => value && SAVE_PASSWORD_RE.test(String(value)));
  }

  // A new password whose confirmation differs will be rejected by the site;
  // prompting for it would save a wrong password and block the retry's prompt.
  function newPasswordsAgree(snapshot) {
    const { passwordField: field, password, scope } = snapshot;
    if (!field || !scope || !snapshot.newPassword) return true;
    // Fields found by a repeated value agree by construction; labelled ones
    // must all hold the same value.
    return scopeInputs(scope)
      .filter(
        (input) =>
          input.type === "password" &&
          input.value &&
          isNewPasswordInput(input) &&
          isUsableInput(input),
      )
      .every((input) => input.value === password);
  }

  // Only real submit controls prompt at once. Every other button, including
  // ones outside the password's form (cookie banners, menus, "Continue" on a
  // form-less login), must be confirmed by the page leaving the password step.
  function submitsImmediately(control) {
    if (!(
      control instanceof HTMLButtonElement ||
      control instanceof HTMLInputElement
    ))
      return false;
    const explicit = String(control.getAttribute("type") || "").toLowerCase();
    // A button's default type is submit, but outside a form it submits nothing.
    return (
      ["submit", "image"].includes(control.type) &&
      Boolean(control.form || ["submit", "image"].includes(explicit))
    );
  }

  function registerRoot(root) {
    if (disposed || rootControllers.has(root)) return;
    rootControllers.set(root, new AbortController());
    // Remember the last username typed on this domain so password-only
    // login steps (and the save prompt) know which account is logging in.
    listen(root, "input", (e) => {
      const t = e.composedPath?.()[0] || e.target;
      if (
        !e.isTrusted ||
        !(t instanceof HTMLInputElement) ||
        !isCaptureInput(t)
      )
        return;
      credentialUserIntent = true;
      credentials.lastInput = t;
      if (USERNAME_INPUT_TYPES.has(t.type) && t.value.trim()) {
        storeUsernameForLater(t.value.trim());
      }
    });

    listen(root, "focusin", (e) => {
      const target = e.composedPath?.()[0] || e.target;
      const targetRoot = target.getRootNode?.();
      if (targetRoot?.host && !rootControllers.has(targetRoot))
        observer.scan(targetRoot);
      if (target instanceof HTMLInputElement && isCaptureInput(target)) {
        credentials.lastInput = target;
      }
    });

    const submissionCoordinator =
      PasswordManagerFormSubmission.createSubmissionCoordinator({
        isForm: (form) => form instanceof HTMLFormElement,
        credentialsFor: (form) => {
          const found = findLoginCredentials(form);
          return newPasswordsAgree(found) ? found : { username: "", password: "" };
        },
        shouldIgnore: () => disposed || !credentialAttempt.idle,
        userActivated: () => navigator.userActivation?.isActive === true,
        handle: ({ credentials }) => attemptCredentials(credentials),
      });
    listen(root, "submit", (event) => {
      if (
        event.isTrusted &&
        navigator.userActivation?.isActive === true &&
        event.target instanceof HTMLFormElement
      ) {
        const username = usernameFromScope(event.target);
        if (username) rememberUsernameAcrossNavigation(username);
      }
      submissionCoordinator.onSubmit(event).catch((error) => {
        console.log("Password Manager submission error:", error);
      });
    });

    // Multi-step login pages frequently use a type=button or a scripted
    // control to swap the password step for TOTP without submitting a form or
    // navigating. Capture the credential snapshot before that handler clears
    // or removes the password input. Submit controls and Enter prompt after a
    // microtask, so a normal submit event can take ownership; other buttons
    // prompt only once the page leaves the password step.
    const handlePossibleAdvance = (source, immediate) => {
      const input =
        source instanceof HTMLInputElement && isCaptureInput(source)
          ? source
          : credentials.lastInput;
      const scope =
        source?.form ||
        source?.closest?.("form, [role='form'], dialog") ||
        (input ? credentialScope(input) : null);
      if (!scope) return;
      credentialUserIntent = true;
      const username = usernameFromScope(scope);
      const snapshot = credentialsFromScope(scope);
      pendingAdvance?.cancel();
      pendingAdvance = null;
      if (!newPasswordsAgree(snapshot)) return;
      pendingAdvance = PasswordManagerFormSubmission.scheduleCredentialAdvance(
        {
          username: username || snapshot.username,
          password: snapshot.password,
        },
        {
          remember: rememberUsernameAcrossNavigation,
          shouldIgnore: () => disposed || !credentialAttempt.idle,
          advanced:
            immediate || savesNewPassword(source, snapshot)
              ? null
              : () => !disposed && leftPasswordStep(snapshot),
          prompt: (captured) => {
            attemptCredentials(captured).catch((error) =>
              console.log("Password Manager credential prompt error:", error),
            );
          },
        },
      );
    };

    listen(root, "click", (event) => {
      const target = event.composedPath?.()[0] || event.target;
      if (
        !event.isTrusted ||
        !(target instanceof Element) ||
        isExtensionUi(target)
      )
        return;
      const control = target.closest(ADVANCE_CONTROLS);
      if (!control || isExtensionUi(control) || isVisibilityToggle(control))
        return;
      handlePossibleAdvance(control, submitsImmediately(control));
    });

    listen(root, "keydown", (event) => {
      if (!event.isTrusted || event.key !== "Enter" || event.isComposing)
        return;
      const target = event.composedPath?.()[0] || event.target;
      if (!(target instanceof HTMLInputElement) || !isCaptureInput(target))
        return;
      handlePossibleAdvance(target, true);
    });
  }
  // ===============================
  // Request credentials from background
  // ===============================
  async function start() {
    await restoreUsernameFromPreviousStep();
    if (disposed) return;

    // Do not place plaintext vault credentials in every matching page at load.
    // Only the secure picker delivers a selected vault secret.
    observer.observeInputs();
    // Page changes before observation began are not in any mutation record.
    duo.mutated();
  }

  // Catch logins that navigate/redirect without a form submit event (e.g. fetch
  // + window.location, a scripted <div> "Sign in", or form.submit() in JS). The
  // extension window and background-owned operation survive the page being
  // destroyed. The entry point calls this before disposing the controller.
  function handlePageHide(event) {
    if (disposed || !event?.isTrusted) return;
    const advance = pendingAdvance?.pending ? pendingAdvance : null;
    pendingAdvance = null;
    advance?.cancel();
    if (!credentialUserIntent || !credentialAttempt.idle || !contextValid())
      return;
    withVisibilityCache(() => {
      // A click that has not yet been confirmed as a login step is confirmed
      // by leaving the page; use what it captured before its handler ran.
      const { username: rawUsername, password } = advance?.credentials.password
        ? advance.credentials
        : findLoginCredentials();
      if (!password) {
        const username = credentials.lastInput
          ? usernameFromScope(credentialScope(credentials.lastInput))
          : "";
        if (username) rememberUsernameAcrossNavigation(username);
        return;
      }
      const username = resolveUsername(rawUsername);
      if (rawUsername) storeUsernameForLater(rawUsername);

      if (!credentialAttempt.reserve()) return;
      chrome.runtime.sendMessage(
        { action: "openCredentialPrompt", username, password },
        () => void chrome.runtime.lastError,
      );
    });
  }

  function dispose() {
    if (disposed) return;
    disposed = true;
    pendingAdvance?.cancel();
    pendingAdvance = null;
    credentialAttempt.dispose();
    observer?.dispose();
    generator.dispose();
    controls.dispose();
    bridge.dispose();
    duo?.dispose();
    credentials.dispose();
    chrome.runtime.onMessage.removeListener(shortcutListener);
    chrome.runtime.onMessage.removeListener(popupFillListener);
  }
  return {
    start,
    dispose,
    handlePageHide,
    roots: () => [...rootControllers.keys()],
  };
};
