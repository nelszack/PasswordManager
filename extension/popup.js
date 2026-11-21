let pendingOperations = [];
let reviewedOperationId = null;
const sendMessage = PasswordManagerUiTransport.send;
const element = id => document.getElementById(id);

function renderStatus(status) {
    const lockButton = element("lockBtn");

    if (Array.isArray(status.pendingOperations)) pendingOperations = status.pendingOperations;
    const operations = pendingOperations;
    const recovery = element("recovery");
    if (recovery) {
        recovery.hidden = operations.length === 0;
        const select = element("operation");
        const previous = select.value;
        select.replaceChildren(
            ...operations.map(record => {
                const option = document.createElement("option");
                option.value = record.operationId;
                option.textContent = PasswordManagerPopupState.operationLabel(record);
                return option;
            })
        );
        if (operations.some(record => record.operationId === previous)) select.value = previous;
        if (select.value !== previous) resetReview();
    }
    const presentation = PasswordManagerPopupState.presentation(status);
    element("statusDot").style.background = presentation.color;
    element("statusText").innerText = presentation.text;
    lockButton.disabled = !presentation.canLock;
    element("nativeHint").textContent = PasswordManagerPopupState.hint(status);
    element("openDesktopBtn").textContent = PasswordManagerPopupState.desktopLabel(status);
}

async function refreshStatus() {
    const status = await sendMessage({ action: "getStatus" });
    if (status) renderStatus(status);
}

chrome.runtime.onMessage.addListener(message => {
    if (message.action === "statusChanged" && message.status) {
        renderStatus(message.status);
    }
});

// Generator: settings persist in pmGenerator, shared with the in-page ✨ button.
let generatorStored = {};
function generatorView() {
    // Invalid stored settings (from an older version or manual edits) fall back to defaults.
    let settings;
    try {
        settings = PasswordManagerGenerator.validate(generatorStored);
    } catch (_) {
        settings = PasswordManagerGenerator.defaults;
    }
    const passphrase = settings.mode === "passphrase";
    element("genLength").value = String(passphrase ? settings.words : settings.length);
    element("genLength").min = passphrase ? "3" : "8";
    element("genLength").max = passphrase ? "12" : "64";
    element("genLength").setAttribute("aria-label", passphrase ? "Number of words" : "Password length");
    element("genLengthValue").textContent = passphrase ? `${settings.words} words` : `${settings.length}`;
    element("genSymbols").checked = settings.symbols;
    element("genSymbols").disabled = passphrase;
    element("genPassphrase").checked = passphrase;
    element("genValue").textContent = PasswordManagerGenerator.generate(settings);
}
function saveGenerator(changes) {
    generatorStored = PasswordManagerPopupState.generatorSettings(generatorStored, changes);
    chrome.storage.local.set({ pmGenerator: generatorStored });
    generatorView();
}
element("genNew").addEventListener("click", generatorView);
element("genLength").addEventListener("input", event => {
    const value = Number(event.target.value);
    saveGenerator(element("genPassphrase").checked ? { words: value } : { length: value });
});
element("genSymbols").addEventListener("change", event => saveGenerator({ symbols: event.target.checked }));
element("genPassphrase").addEventListener("change", event => saveGenerator({ passphrase: event.target.checked }));
element("genCopy").addEventListener("click", async () => {
    const value = element("genValue").textContent;
    if (!value) return;
    try {
        await navigator.clipboard.writeText(value);
        element("output").innerText = "Password copied. Paste it, then generate a new one for the next site.";
    } catch (_) {
        element("output").innerText = "Could not copy. Select the password and copy it manually.";
    }
});

// Sites where the user chose "Never for this site" in the save prompt.
function renderNeverSave(sites) {
    element("neverSave").hidden = sites.length === 0;
    element("neverCount").textContent = String(sites.length);
    element("neverList").replaceChildren(
        ...sites.map(site => {
            const item = document.createElement("li");
            const label = document.createElement("span");
            label.textContent = site;
            const allow = document.createElement("button");
            allow.textContent = "Allow";
            allow.setAttribute("aria-label", `Offer to save logins on ${site} again`);
            allow.addEventListener("click", () => {
                const remaining = sites.filter(value => value !== site);
                chrome.storage.local.set({ pmNeverSave: remaining });
                renderNeverSave(remaining);
            });
            item.append(label, allow);
            return item;
        })
    );
}

document.addEventListener("DOMContentLoaded", () => {
    chrome.storage.local.get(["pmStatus", "pmGenerator", "pmNeverSave"], result => {
        generatorStored = result.pmGenerator && typeof result.pmGenerator === "object" ? result.pmGenerator : {};
        generatorView();
        renderNeverSave(PasswordManagerPopupState.neverSaveSites(result.pmNeverSave));
        if (result.pmStatus) renderStatus(result.pmStatus);
        refreshStatus();
    });
});

element("lockBtn").addEventListener("click", async () => {
    const response = await sendMessage({ action: "lockVault" });
    element("output").innerText = response?.success
        ? response.data
        : response?.error || "Could not reach the desktop app";
    await refreshStatus();
});

function resetReview() {
    reviewedOperationId = null;
    element("unknownReview").hidden = true;
    element("inspected").checked = false;
    element("acknowledgeOperation").disabled = true;
}
element("operation").addEventListener("change", resetReview);
element("inspected").addEventListener("change", event => {
    element("acknowledgeOperation").disabled = !event.target.checked;
});
element("reviewOperation").addEventListener("click", async () => {
    resetReview();
    const operationId = element("operation").value;
    const result = await sendMessage({ action: "reconcileOperation", operationId });
    element("output").innerText = result?.success
        ? `Operation: ${result.data.state}`
        : result?.error || "Outcome unavailable";
    if (operationId !== element("operation").value) return;
    reviewedOperationId = result?.success && result.data.state === "unknown" ? operationId : null;
    element("unknownReview").hidden = reviewedOperationId === null;
    await refreshStatus();
});
element("acknowledgeOperation").addEventListener("click", async () => {
    if (!element("inspected").checked || reviewedOperationId !== element("operation").value) return;
    const operationId = element("operation").value;
    const result = await sendMessage({ action: "acknowledgeUnknownOperation", operationId, inspected: true });
    element("output").innerText = result?.success
        ? "Reviewed outcome acknowledged"
        : result?.error || "Acknowledgement failed";
    resetReview();
    await refreshStatus();
});

element("openDesktopBtn").addEventListener("click", async () => {
    const button = element("openDesktopBtn");
    button.disabled = true;
    element("output").innerText = "Opening desktop app…";
    const response = await sendMessage({ action: "openDesktop" });
    element("output").innerText = response?.success
        ? "Desktop app launch requested."
        : response?.error || "Could not open the desktop app";
    button.disabled = false;
});
