const token = new URLSearchParams(location.search).get("token");
const items = document.getElementById("items");
const status = document.getElementById("status");
const title = document.getElementById("title");
const confirmation = document.getElementById("confirmCrossOrigin");
let crossOrigin = false;

function send(message) {
    return new Promise(resolve => chrome.runtime.sendMessage(message, resolve));
}

async function complete(id) {
    if (crossOrigin && !confirmation.checked) {
        status.textContent = "Confirm the embedded site's origin before filling";
        return;
    }
    const response = await send({
        action: "completeSecurePicker", token, id,
        confirmCrossOrigin: crossOrigin && confirmation.checked
    });
    if (response?.success) window.close();
    else status.textContent = response?.error || "Selection failed";
}

async function load() {
    if (!token) throw new Error("Missing picker token");
    const response = await send({ action: "getSecurePickerData", token });
    if (!response?.success) throw new Error(response?.error || "Picker unavailable");
    if (response.loading) {
        status.textContent = "Loading saved items…";
        setTimeout(() => load().catch(showError), 150);
        return;
    }
    if (response.error) throw new Error(response.error);
    title.textContent = PasswordManagerPickerState.title(response.kind);
    document.getElementById("destination").textContent = `Fill on: ${response.origin}`;
    crossOrigin = response.crossOrigin === true;
    document.getElementById("crossOriginWarning").hidden = !crossOrigin;
    document.getElementById("crossOriginText").textContent =
        `Allow filling ${response.origin}, embedded in ${response.topOrigin}`;
    status.textContent = PasswordManagerPickerState.status(response.items);
    items.replaceChildren();
    for (const item of response.items) {
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = PasswordManagerPickerState.itemLabel(item);
        if (item.username && item.username !== item.name) {
            const username = document.createElement("small");
            username.textContent = item.username;
            button.appendChild(username);
        }
        button.addEventListener("click", event => {
            if (event.isTrusted) complete(item.id);
        });
        items.appendChild(button);
    }
}

function showError(error) {
    status.textContent = error?.message || "Picker unavailable";
}

document.getElementById("cancel").addEventListener("click", async event => {
    if (!event.isTrusted) return;
    await send({ action: "completeSecurePicker", token, cancel: true });
    window.close();
});

load().catch(showError);
