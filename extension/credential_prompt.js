const token = new URLSearchParams(location.search).get("token");
const form = document.getElementById("credentials");
const site = document.getElementById("site");
const status = document.getElementById("status");
const nameInput = document.getElementById("name");
const usernameInput = document.getElementById("username");
const usernameLabel = document.getElementById("usernameLabel");
const updateButton = document.getElementById("update");
const updateNote = document.getElementById("updateNote");
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
    const data = response.data;
    site.textContent = data.site;
    status.textContent = data.message;
    nameInput.value = data.suggestedName;
    usernameInput.value = data.username;
    usernameInput.hidden = !data.askForUsername;
    usernameLabel.hidden = !data.askForUsername;
    updateButton.hidden = !data.hasAccounts;
    if (data.updateTarget?.name) {
        updateButton.textContent = `Update “${data.updateTarget.name}”`;
    }
    updateNote.textContent = data.updateNote || "";
    updateNote.hidden = !data.hasAccounts || !data.updateNote;
    form.hidden = false;
    (data.askForUsername ? usernameInput : nameInput).focus();
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
