"use strict";
// Page entry; scripts/build_extension.cjs bundles it into passkey_prompt_runtime.js.
const PasswordManagerUiTransport = require("./ui_transport.js");
require("./ui_session.js");
// The decision window for one browser passkey request. It shows the site from
// the browser (never from the page) and needs an explicit choice.
const token = new URLSearchParams(location.search).get("token");
const element = id => document.getElementById(id);
const send = message => PasswordManagerUiTransport.request(message, "Passkey window unavailable");
let selected = null;
let busy = false;

function host(origin) {
    try {
        return new URL(origin).host;
    } catch (_) {
        return origin;
    }
}

function render(data) {
    const site = host(data.origin);
    const create = data.kind === "create";
    element("title").textContent = create ? "Save a passkey" : "Sign in with a passkey";
    element("destination").textContent = create
        ? `${site} wants to save a passkey for “${data.user}” in your vault.`
        : `${site} is asking you to sign in with a saved passkey.`;
    element("confirm").textContent = create ? "Save passkey" : "Sign in";
    // Proof that it is you is given in the desktop app, never typed here.
    if (!data.locked && data.canConfirm === true && data.verification !== "discouraged") {
        const box = element("confirmInDesktop");
        const required = data.verification === "required";
        element("verify").hidden = false;
        box.checked = required;
        box.disabled = required;
        element("verifyHint").textContent = required
            ? "This site requires proof that it is you. After you continue, confirm with your master password or passkey PIN in the desktop app."
            : "Optional: some sites need this to sign you in without a password. You confirm with your master password or passkey PIN in the desktop app.";
    }
    element("openDesktop").hidden = !data.locked;
    if (data.locked) {
        element("status").textContent =
            "Your vault is locked. Unlock it in the desktop app; this window continues by itself. Or use another provider.";
        element("confirm").disabled = true;
        return;
    }
    if (data.canConfirm !== true && data.verification === "required") {
        element("status").textContent =
            "This site requires proof that it is you, and this vault has no master password or passkey PIN to confirm with. Set a passkey PIN in the desktop app (Settings → Security), or use another passkey provider.";
        element("confirm").disabled = true;
        return;
    }
    element("status").textContent = create ? `Relying party: ${data.rp}` : "Choose the account to sign in with.";
    const choices = element("choices");
    choices.replaceChildren(
        ...data.choices.map((choice, index) => {
            const label = document.createElement("label");
            const radio = document.createElement("input");
            radio.type = "radio";
            radio.name = "passkey";
            radio.value = String(choice.id);
            radio.addEventListener("change", () => {
                selected = choice.id;
                element("confirm").disabled = false;
            });
            const text = document.createElement("span");
            text.textContent = choice.displayName && choice.displayName !== choice.userName
                ? `${choice.displayName} (${choice.userName})`
                : choice.userName;
            label.append(radio, text);
            if (index === 0) {
                radio.checked = true;
                selected = choice.id;
            }
            return label;
        })
    );
    element("confirm").disabled = !create && selected === null;
}

async function finish(selection) {
    if (busy) return;
    busy = true;
    const waiting = selection.confirmInDesktop === true;
    // While waiting for the desktop app, Cancel stays available.
    const controls = waiting ? ["confirm", "fallback"] : ["confirm", "fallback", "cancel"];
    for (const id of controls) element(id).disabled = true;
    if (waiting) element("status").textContent = "Confirm it's you in the desktop app…";
    try {
        const result = await send({ action: "completePasskeyPrompt", token, selection });
        if (result?.success === false) throw new Error(result.error || "Passkey request failed");
        window.close();
    } catch (error) {
        element("status").textContent = error.message || "Passkey request failed";
        // The request may still be open (for example after a refusal).
        for (const id of controls) element(id).disabled = false;
    } finally {
        busy = false;
    }
}

element("confirm").addEventListener("click", event => {
    if (event.isTrusted === false) return;
    const confirmInDesktop = !element("verify").hidden && element("confirmInDesktop").checked === true;
    finish({ action: "confirm", id: selected, ...(confirmInDesktop ? { confirmInDesktop } : {}) });
});
element("fallback").addEventListener("click", () => finish({ action: "fallback" }));
element("cancel").addEventListener("click", () => {
    if (!busy) return finish({ action: "cancel" });
    // Cancelling while the desktop app is asked ends the request at once.
    send({ action: "completePasskeyPrompt", token, selection: { action: "cancel" } }).finally(() => window.close());
});

function load(refresh = false) {
    return send({ action: "getPasskeyPromptData", token, ...(refresh ? { refresh: true } : {}) }).then(render, error => {
        element("status").textContent = error.message || "Passkey request expired";
        element("confirm").disabled = true;
    });
}
element("openDesktop").addEventListener("click", event => {
    if (event.isTrusted === false) return;
    PasswordManagerUiTransport.send({ action: "openDesktop" }).then(response => {
        if (!response?.success) element("status").textContent = response?.error || "Could not open the desktop app";
    });
});
// Continue once the vault is unlocked in the desktop app.
chrome.runtime.onMessage?.addListener?.(message => {
    const unlocked = message?.action === "statusChanged" && message.status?.running && !message.status.locked;
    if (unlocked && !element("openDesktop").hidden && !busy) load(true);
});
load();
