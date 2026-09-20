const token = new URLSearchParams(location.search).get("token");
const form = document.getElementById("credentials");
const site = document.getElementById("site");
const status = document.getElementById("status");
const nameInput = document.getElementById("name");
const usernameInput = document.getElementById("username");
const usernameLabel = document.getElementById("usernameLabel");
const updateButton = document.getElementById("update");
let completing = false;

function send(message) {
    return new Promise(resolve => chrome.runtime.sendMessage(message, resolve));
}

function showError(error) {
    completing = false;
    status.textContent = error?.message || "Credential prompt unavailable";
}

async function complete(action) {
    if (completing) return;
    if (action !== "cancel" && !form.reportValidity()) return;
    completing = true;
    const response = await send({
        action: "completeCredentialPrompt",
        token,
        selection: {
            action,
            name: nameInput.value,
            username: usernameInput.value
        }
    });
    if (response?.success) window.close();
    else showError(new Error(response?.error || "Could not save credentials"));
}

async function load() {
    if (!token) throw new Error("Missing credential prompt token");
    const response = await send({ action: "getCredentialPromptData", token });
    if (!response?.success) throw new Error(response?.error || "Credential prompt unavailable");
    if (response.loading) {
        status.textContent = "Checking saved credentials…";
        setTimeout(() => load().catch(showError), 150);
        return;
    }
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
        updateButton.textContent = `Update ${data.updateTarget.name}`;
    }
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

load().catch(showError);
