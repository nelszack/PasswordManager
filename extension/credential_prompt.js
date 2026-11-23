const token = new URLSearchParams(location.search).get("token");
const form = document.getElementById("credentials");
const site = document.getElementById("site");
const status = document.getElementById("status");
const nameInput = document.getElementById("name");
const usernameInput = document.getElementById("username");
const usernameLabel = document.getElementById("usernameLabel");
const updateButton = document.getElementById("update");
const updateNote = document.getElementById("updateNote");
const passwordMask = document.getElementById("passwordMask");
const passwordInput = document.getElementById("password");
const revealButton = document.getElementById("revealPassword");
const chooseOtherButton = document.getElementById("chooseOther");
const chooser = document.getElementById("chooser");
const targetSearch = document.getElementById("targetSearch");
const targetResults = document.getElementById("targetResults");
let passwordEdited = false;
let completing = false;
let uncertain = false;

const send = PasswordManagerUiTransport.send;

function showError(error) {
    completing = false;
    status.textContent = error?.message || "Credential prompt unavailable";
}

async function complete(action) {
    if (completing) return;
    const dismissing = action === "cancel" || action === "never";
    if (uncertain && !dismissing) return;
    if (!dismissing && !form.reportValidity()) return;
    completing = true;
    const response = await send({
        action: "completeCredentialPrompt",
        token,
        selection: {
            action,
            name: nameInput.value,
            username: usernameInput.value,
            // Only a revealed, edited password replaces the captured one.
            ...(passwordEdited && passwordInput.value ? { password: passwordInput.value } : {}),
        },
    });
    if (response?.success) window.close();
    else {
        uncertain = Boolean(response?.uncertain);
        if (uncertain) {
            document.getElementById("reviewOutcome").hidden = false;
            updateButton.disabled = true;
            document.getElementById("add").disabled = true;
        }
        showError(new Error(response?.error || "Could not save credentials"));
    }
}

async function load() {
    if (!token) throw new Error("Missing credential prompt token");
    const response = await send({ action: "getCredentialPromptData", token });
    if (!response?.success) throw new Error(response?.error || "Credential prompt unavailable");
    if (response.error) throw new Error(response.error);
    render(response.data, true);
}

function render(data, first) {
    site.textContent = data.site;
    status.textContent = data.message;
    if (first) {
        nameInput.value = data.suggestedName;
        usernameInput.value = data.username;
    }
    usernameInput.hidden = !data.askForUsername;
    usernameLabel.hidden = !data.askForUsername;
    updateButton.hidden = !data.hasAccounts;
    // One primary action: update when an account matches, otherwise save new.
    const updateFirst =
        data.hasAccounts &&
        Boolean(data.updateTarget) &&
        ((!data.askForUsername && !data.updateNote) || data.preferUpdate === true);
    updateButton.className = updateFirst ? "primary" : "";
    document.getElementById("add").className = updateFirst ? "" : "primary";
    if (data.updateTarget?.name) {
        updateButton.textContent = `Update “${data.updateTarget.name}”`;
    }
    const length = Number(data.passwordLength) || 0;
    passwordMask.textContent = length ? `${"•".repeat(Math.min(length, 16))} (${length} characters)` : "";
    updateNote.textContent = data.updateNote || "";
    updateNote.hidden = !data.hasAccounts || !data.updateNote;
    form.hidden = false;
    if (first) (data.preferUpdate === true ? updateButton : data.askForUsername ? usernameInput : nameInput).focus();
}

// Choose any saved login to update, for when its saved address differs from this site.
chooseOtherButton.addEventListener("click", event => {
    if (!event.isTrusted) return;
    chooser.hidden = !chooser.hidden;
    chooseOtherButton.setAttribute("aria-expanded", String(!chooser.hidden));
    if (!chooser.hidden) targetSearch.focus();
});
// The search box sits inside the save form: Enter must not save a new login, and
// Escape closes the search rather than the whole prompt.
targetSearch.addEventListener("keydown", event => {
    if (event.key === "Enter") {
        event.preventDefault();
        targetResults.querySelector("button")?.focus();
    } else if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        chooser.hidden = true;
        chooseOtherButton.setAttribute("aria-expanded", "false");
        chooseOtherButton.focus();
    }
});
let searchTimer = null;
let searchSerial = 0;
targetSearch.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => searchTargets().catch(showError), 200);
});
async function searchTargets() {
    const serial = ++searchSerial;
    const query = targetSearch.value.trim();
    if (query.length < 2) {
        targetResults.replaceChildren();
        return;
    }
    const response = await send({ action: "searchCredentialTargets", token, query });
    if (serial !== searchSerial) return;
    if (!response?.success) throw new Error(response?.error || "Search failed");
    const rows = response.items.map(item => {
        const button = document.createElement("button");
        button.type = "button";
        const name = document.createElement("span");
        name.textContent = item.name || item.username || "Unnamed login";
        const detail = document.createElement("span");
        detail.className = "detail";
        detail.textContent = [item.username, item.site].filter(Boolean).join(" · ");
        button.append(name, detail);
        button.addEventListener("click", event => {
            if (event.isTrusted) chooseTarget(item.id).catch(showError);
        });
        const row = document.createElement("li");
        row.append(button);
        return row;
    });
    if (!rows.length) {
        const empty = document.createElement("li");
        empty.className = "detail";
        empty.textContent = "No saved login matches.";
        rows.push(empty);
    }
    targetResults.replaceChildren(...rows);
}
async function chooseTarget(entryId) {
    const response = await send({ action: "chooseCredentialTarget", token, entryId });
    if (!response?.success) throw new Error(response?.error || "Could not choose that login");
    render(response.data, false);
    chooser.hidden = true;
    chooseOtherButton.setAttribute("aria-expanded", "false");
    updateButton.focus();
}

form.addEventListener("submit", event => {
    event.preventDefault();
    if (event.isTrusted) complete("add").catch(showError);
});
updateButton.addEventListener("click", event => {
    if (event.isTrusted) complete("update").catch(showError);
});
document.getElementById("cancel").addEventListener("click", event => {
    if (event.isTrusted) complete("cancel").catch(showError);
});
document.getElementById("never").addEventListener("click", event => {
    if (event.isTrusted) complete("never").catch(showError);
});

// Like the desktop and Android apps, a shown password hides again after 15 seconds
// without editing, or when this window loses focus. Edits are kept.
let concealTimer = null;
function concealPassword() {
    clearTimeout(concealTimer);
    passwordInput.hidden = true;
    passwordMask.hidden = false;
    revealButton.textContent = "Show";
}
function concealLater() {
    clearTimeout(concealTimer);
    concealTimer = setTimeout(concealPassword, 15000);
    concealTimer?.unref?.();
}
globalThis.addEventListener?.("blur", () => {
    if (!passwordInput.hidden) concealPassword();
});

// Review or correct the captured password before saving.
revealButton.addEventListener("click", async event => {
    if (!event.isTrusted) return;
    if (!passwordInput.hidden) {
        concealPassword();
        return;
    }
    if (!passwordEdited) {
        const response = await send({ action: "revealCredentialPassword", token });
        if (!response?.success) {
            showError(new Error(response?.error || "Password unavailable"));
            return;
        }
        passwordInput.value = response.password;
    }
    passwordInput.hidden = false;
    passwordMask.hidden = true;
    revealButton.textContent = "Hide";
    passwordInput.focus();
    concealLater();
});
passwordInput.addEventListener("input", () => {
    passwordEdited = true;
    concealLater();
    passwordMask.textContent = `${"•".repeat(Math.min(passwordInput.value.length, 16))} (${passwordInput.value.length} characters)`;
});
// Escape means "Not now", like closing the window.
document.addEventListener("keydown", event => {
    if (event.key === "Escape" && event.isTrusted && !event.repeat) complete("cancel").catch(showError);
});

document.getElementById("reviewOutcome").addEventListener("click", event => {
    if (!event.isTrusted || completing) return;
    completing = true;
    send({ action: "reviewCredentialPrompt", token })
        .then(response => {
            completing = false;
            if (!response?.success) throw new Error(response?.error || "Could not check save outcome");
            const state = response.data.state;
            if (["committed", "failed"].includes(state)) window.close();
            else if (state === "committed_durability_unknown") {
                status.textContent =
                    "Saved, but storage durability is uncertain. Inspect your storage before closing the vault.";
                document.getElementById("reviewOutcome").hidden = true;
            } else
                status.textContent =
                    state === "pending"
                        ? "The save is still running. Check again shortly."
                        : "The save outcome is unknown. Inspect the vault in the desktop app, then acknowledge the unknown operation in the extension popup.";
        })
        .catch(showError);
});
load().catch(showError);
