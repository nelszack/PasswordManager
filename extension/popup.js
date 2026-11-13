let pendingOperations = [];
let reviewedOperationId = null;
const sendMessage = PasswordManagerUiTransport.send;

function renderStatus(status) {
    const dot = document.getElementById("statusDot");
    const text = document.getElementById("statusText");
    const lockButton = document.getElementById("lockBtn");

    if (Array.isArray(status.pendingOperations)) pendingOperations = status.pendingOperations;
    const operations = pendingOperations;
    const recovery = document.getElementById("recovery");
    if (recovery) {
        recovery.hidden = operations.length === 0;
        const select = document.getElementById("operation");
        const previous = select.value;
        select.replaceChildren(...operations.map(record => {
            const option = document.createElement("option");
            option.value = record.operationId;
            option.textContent = `${record.action}: ${record.operationId}`;
            return option;
        }));
        if (operations.some(record => record.operationId === previous)) select.value = previous;
        if (select.value !== previous) resetReview();
    }
    const presentation = PasswordManagerPopupState.presentation(status);
    dot.style.background = presentation.color;
    text.innerText = presentation.text;
    lockButton.disabled = !presentation.canLock;
    const hint = document.getElementById("nativeHint");
    if (hint) hint.textContent = !status.native
        ? "Open the desktop app and check browser integration settings."
        : !status.running ? "Open the desktop app to start the server and unlock your vault."
        : status.locked ? "Open the desktop app to unlock your vault."
        : "Use the key button beside a website’s login field to choose an account.";
}

async function refreshStatus() {
    const status = await sendMessage({ action: "getStatus" });
    if (status) renderStatus(status);
}

chrome.runtime.onMessage.addListener((message) => {
    if (message.action === "statusChanged" && message.status) {
        renderStatus(message.status);
    }
});

document.addEventListener("DOMContentLoaded", () => {
    chrome.storage.local.get("pmStatus", result => {
        if (result.pmStatus) renderStatus(result.pmStatus);
        refreshStatus();
    });
});

document.getElementById("lockBtn").addEventListener("click", async () => {
    const response = await sendMessage({ action: "lockVault" });
    document.getElementById("output").innerText = response?.success
        ? response.data
        : response?.error || "Could not contact the native host";
    await refreshStatus();
});

function resetReview() {
    reviewedOperationId = null;
    document.getElementById("unknownReview").hidden = true;
    document.getElementById("inspected").checked = false;
    document.getElementById("acknowledgeOperation").disabled = true;
}
document.getElementById("operation").addEventListener("change", resetReview);
document.getElementById("inspected").addEventListener("change", event => {
    document.getElementById("acknowledgeOperation").disabled = !event.target.checked;
});
document.getElementById("reviewOperation").addEventListener("click", async () => {
    resetReview();
    const operationId = document.getElementById("operation").value;
    const result = await sendMessage({ action: "reconcileOperation", operationId });
    document.getElementById("output").innerText = result?.success ? `Operation: ${result.data.state}` : result?.error || "Outcome unavailable";
    if (operationId !== document.getElementById("operation").value) return;
    reviewedOperationId = result?.success && result.data.state === "unknown" ? operationId : null;
    document.getElementById("unknownReview").hidden = reviewedOperationId === null;
    await refreshStatus();
});
document.getElementById("acknowledgeOperation").addEventListener("click", async () => {
    if (!document.getElementById("inspected").checked || reviewedOperationId !== document.getElementById("operation").value) return;
    const operationId = document.getElementById("operation").value;
    const result = await sendMessage({ action: "acknowledgeUnknownOperation", operationId, inspected: true });
    document.getElementById("output").innerText = result?.success ? "Reviewed outcome acknowledged" : result?.error || "Acknowledgement failed";
    resetReview();
    await refreshStatus();
});
