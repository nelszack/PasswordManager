"use strict";
// Page entry; scripts/build_extension.cjs bundles it into picker_runtime.js.
const PasswordManagerUiTransport = require("./ui_transport.js");
require("./ui_session.js");
const PasswordManagerPickerState = require("./picker_state.js");
const token = new URLSearchParams(location.search).get("token");
const items = document.getElementById("items");
const status = document.getElementById("status");
const title = document.getElementById("title");
const confirmation = document.getElementById("confirmCrossOrigin");
let crossOrigin = false;
let pickerKind = "login";
let savedItems = [];
let visibleItems = [];
let activeIndex = -1;
// Selections are ignored briefly after items appear, so a double-click or held
// key that opened this window cannot also choose an account in it.
const INPUT_GUARD_MS = 500;
let readyAt = Infinity;
const search = document.getElementById("search");
const recovery = document.getElementById("recovery");

const send = PasswordManagerUiTransport.send;

async function complete(id) {
    if (Date.now() < readyAt) return;
    if (crossOrigin && !confirmation.checked) {
        status.textContent = "Confirm the embedded site's origin before filling";
        return;
    }
    const response = await send({
        action: "completeSecurePicker",
        token,
        id,
        confirmCrossOrigin: crossOrigin && confirmation.checked,
    });
    if (response?.success) window.close();
    else showError({ message: response?.error || "Selection failed" });
}

async function load(retry = false) {
    if (!token) throw new Error("Missing picker token");
    const response = await send({ action: "getSecurePickerData", token, ...(retry ? { retry: true } : {}) });
    if (!response?.success) throw new Error(response?.error || "Picker unavailable");
    if (response.error) throw new Error(response.error);
    title.textContent = PasswordManagerPickerState.title(response.kind);
    document.getElementById("destination").textContent = `Fill on: ${response.origin}`;
    crossOrigin = response.crossOrigin === true;
    document.getElementById("crossOriginWarning").hidden = !crossOrigin;
    document.getElementById("crossOriginText").textContent =
        `Allow filling ${response.origin}, embedded in ${response.topOrigin}`;
    savedItems = response.items;
    // Zero matches is a normal state; the unlock card is only for errors (shown by showError).
    recovery.hidden = true;
    search.hidden = response.items.length < 2;
    readyAt = Date.now() + INPUT_GUARD_MS;
    pickerKind = response.kind;
    renderItems();
    setTimeout(() => {
        for (const button of items.children) button.disabled = false;
    }, INPUT_GUARD_MS);
    // Focus search only; never pre-focus an account, so no single key fills one.
    if (!search.hidden) search.focus();
}

function renderItems() {
    items.replaceChildren();
    const query = search.value.trim();
    visibleItems = PasswordManagerPickerState.rank(savedItems, query);
    // Typing highlights the best match so Enter fills it.
    activeIndex = query && visibleItems.length ? 0 : -1;
    status.textContent =
        query && !visibleItems.length
            ? "No accounts match this search. Clear the search to show all accounts."
            : PasswordManagerPickerState.status(savedItems, pickerKind);
    visibleItems.forEach((item, index) => {
        const button = document.createElement("button");
        button.type = "button";
        button.id = `pm-option-${index}`;
        button.setAttribute("role", "option");
        const avatar = document.createElement("span");
        avatar.className = "avatar";
        avatar.setAttribute("aria-hidden", "true");
        avatar.textContent = PasswordManagerPickerState.initial(item);
        const text = document.createElement("span");
        text.className = "text";
        const name = document.createElement("span");
        name.textContent = PasswordManagerPickerState.itemLabel(item);
        text.appendChild(name);
        if (item.username && item.username !== item.name) {
            const username = document.createElement("small");
            username.textContent = item.username;
            text.appendChild(username);
        }
        button.appendChild(avatar);
        button.appendChild(text);
        button.disabled = Date.now() < readyAt;
        button.addEventListener("click", event => {
            if (event.isTrusted) complete(item.id);
        });
        button.addEventListener("focus", () => highlight(index));
        items.appendChild(button);
    });
    highlight(activeIndex);
}

function highlight(index) {
    activeIndex = index;
    Array.from(items.children).forEach((button, position) => {
        button.className = position === index ? "active" : "";
        button.setAttribute("aria-selected", String(position === index));
        if (position === index) button.setAttribute("aria-current", "true");
        else button.removeAttribute?.("aria-current");
    });
    // Screen readers announce the highlighted account while focus stays in search.
    const active = items.children[index];
    if (active?.id) search.setAttribute("aria-activedescendant", active.id);
    else search.removeAttribute?.("aria-activedescendant");
}

function showError(error) {
    savedItems = [];
    visibleItems = [];
    items.replaceChildren();
    const message = error?.message || "Picker unavailable";
    const kind = PasswordManagerPickerState.failure(message);
    // Offer only the recovery that can help with this failure.
    recovery.hidden = kind === "expired";
    document.getElementById("openDesktop").hidden = kind !== "locked" && kind !== "disconnected";
    status.textContent =
        kind === "expired" ? `${message}. Close this window and choose the field's key button again.` : message;
}

async function cancel() {
    await send({ action: "completeSecurePicker", token, cancel: true });
    window.close();
}

document.getElementById("cancel").addEventListener("click", event => {
    if (event.isTrusted) cancel();
});

document.addEventListener("keydown", event => {
    if (!event.isTrusted) return;
    if (event.key === "Escape") {
        event.preventDefault();
        cancel();
        return;
    }
    if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key) && visibleItems.length) {
        if (event.target === search && ["Home", "End"].includes(event.key)) return;
        event.preventDefault();
        highlight(PasswordManagerPickerState.move(activeIndex, visibleItems.length, event.key));
        const target = items.children[activeIndex];
        // From the list, focus follows the highlight; from search, typing stays possible.
        if (event.target === search) target?.scrollIntoView?.({ block: "nearest" });
        else target?.focus();
        return;
    }
    // Enter fills only an item the user highlighted by typing or with arrow keys.
    if (event.key === "Enter" && event.target === search && !event.repeat && visibleItems[activeIndex]) {
        event.preventDefault();
        complete(visibleItems[activeIndex].id);
    }
});

search.addEventListener("input", renderItems);
document.getElementById("openDesktop")?.addEventListener("click", async event => {
    if (!event.isTrusted) return;
    const response = await send({ action: "openDesktop" });
    status.textContent = response?.success
        ? "Unlock your vault in the desktop app; this window will continue."
        : response?.error || "Could not open the desktop app";
});
// Continue automatically once the vault is unlocked elsewhere.
chrome.runtime.onMessage?.addListener?.(message => {
    const unlocked = message?.action === "statusChanged" && message.status?.running && !message.status.locked;
    if (unlocked && !recovery.hidden) load(true).catch(showError);
});
document.getElementById("retry").addEventListener("click", event => {
    if (event.isTrusted) load(true).catch(showError);
});
load().catch(showError);
