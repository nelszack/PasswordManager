const token = new URLSearchParams(location.search).get("token");
const items = document.getElementById("items");
const status = document.getElementById("status");
const title = document.getElementById("title");
const confirmation = document.getElementById("confirmCrossOrigin");
let crossOrigin = false;
let savedItems = [];
const search = document.getElementById("search");
const recovery = document.getElementById("recovery");

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
    else showError({ message: response?.error || "Selection failed" });
}

async function load(retry = false) {
    if (!token) throw new Error("Missing picker token");
    const response = await send({ action: "getSecurePickerData", token, ...(retry ? { retry: true } : {}) });
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
    savedItems = response.items;
    recovery.hidden = response.items.length > 0;
    renderItems();
}
function renderItems() {
    items.replaceChildren();
    const query = search.value.trim().toLowerCase();
    const matching = savedItems.filter(item => `${item.name} ${item.username || ""}`.toLowerCase().includes(query));
    status.textContent = query && !matching.length ? "No accounts match this search. Clear the search to show all accounts." : PasswordManagerPickerState.status(savedItems);
    for (const item of matching) {
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
    savedItems = []; items.replaceChildren(); recovery.hidden = false;
    status.textContent = error?.message || "Picker unavailable";
}

document.getElementById("cancel").addEventListener("click", async event => {
    if (!event.isTrusted) return;
    await send({ action: "completeSecurePicker", token, cancel: true });
    window.close();
});

search.addEventListener("input", renderItems);
document.getElementById("retry").addEventListener("click", event => { if (event.isTrusted) load(true).catch(showError); });
load().catch(showError);
