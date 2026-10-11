const token = new URLSearchParams(location.search).get("token");
const requests = document.getElementById("requests"), status = document.getElementById("status");
let timer, busy = false, rendered = "", stopped = false;
function send(message) {
    return new Promise((resolve, reject) => chrome.runtime.sendMessage(message, response => {
        if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
        else if (!response?.success) reject(new Error(response?.error || "Duo window unavailable"));
        else resolve(response);
    }));
}
function clearCodes() { for (const input of requests.querySelectorAll("input")) input.value = ""; }
function stop(error) {
    stopped = true; clearTimeout(timer); clearCodes(); requests.replaceChildren();
    status.textContent = error?.message || "Duo window unavailable";
}
async function decide(r, approve, code) {
    if (busy || stopped) return;
    if (r.expires_at * 1000 <= Date.now()) { status.textContent = "Request expired. Checking again…"; await load(); return; }
    if (approve && code && !new RegExp(`^[0-9]{${r.code_digits}}$`).test(code.value)) {
        status.textContent = "Enter the verification code shown on the login page."; code.focus(); return;
    }
    busy = true; clearTimeout(timer);
    const verificationCode = approve ? code?.value || "" : "";
    clearCodes();
    for (const control of requests.querySelectorAll("button,input")) control.disabled = true;
    status.textContent = approve ? "Approving…" : "Denying…";
    try {
        const result = await send({ action: "completeDuoPrompt", token, entryId: r.entryId,
            requestId: r.id, fingerprint: r.fingerprint, approve, verificationCode });
        if (!result.remaining) { stopped = true; window.close(); return; }
        rendered = "";
    } catch (error) { stop(error); }
    finally { busy = false; }
    if (!stopped) await load();
}
function card(r) {
    const row = document.createElement("article");
    const title = document.createElement("h2"); title.textContent = r.entryName || "Duo login"; row.append(title);
    for (const [label, value] of [["Application", r.application], ["Account", r.username], ["Location", r.location],
        ["Summary", r.summary], ["Expires", new Date(r.expires_at * 1000).toLocaleTimeString()]]) {
        const p = document.createElement("p"); p.textContent = `${label}: ${value || "Not provided"}`; row.append(p);
    }
    let code;
    if (r.code_digits && !r.unsupported) {
        const label = document.createElement("label"); label.textContent = `${r.code_digits}-digit code shown on the login page`;
        code = document.createElement("input"); code.type = "password"; code.inputMode = "numeric";
        code.autocomplete = "off"; code.maxLength = r.code_digits;
        label.append(code); row.append(label);
    }
    if (r.unsupported) { const p = document.createElement("p"); p.textContent = `Approval unavailable: ${r.unsupported}`; row.append(p); }
    const actions = document.createElement("div"); actions.className = "actions";
    for (const approve of [true, false]) {
        const button = document.createElement("button"); button.type = "button";
        button.textContent = approve ? "Approve" : "Deny"; button.className = approve ? "approve" : "deny";
        button.disabled = approve && Boolean(r.unsupported);
        button.addEventListener("click", event => { if (event.isTrusted) decide(r, approve, code).catch(stop); });
        actions.append(button);
    }
    row.append(actions); return row;
}
async function load() {
    clearTimeout(timer);
    if (stopped || busy) return;
    try {
        if (!token) throw new Error("Missing Duo window token");
        const response = await send({ action: "getDuoPromptData", token });
        if (stopped || busy) return;
        document.getElementById("destination").textContent = `Login page: ${response.sourceOrigin}`
            + (response.origin !== response.sourceOrigin ? ` · Duo: ${response.origin}` : "");
        const key = JSON.stringify(response.requests.map(r => [r.entryId, r.id, r.fingerprint]));
        if (rendered !== key) { clearCodes(); requests.replaceChildren(...response.requests.map(card)); rendered = key; }
        status.textContent = response.requests.length ? "Review this login, then approve or deny." : "No pending requests.";
        timer = setTimeout(load, 5000);
    } catch (error) { stop(error); }
}
document.getElementById("cancel").addEventListener("click", async event => {
    if (!event.isTrusted || busy) return;
    stopped = true; clearTimeout(timer); clearCodes();
    try { await send({ action: "completeDuoPrompt", token, cancel: true }); window.close(); }
    catch (error) { stop(error); }
});
chrome.runtime.onMessage.addListener(message => {
    if (message.action === "statusChanged" && (!message.status?.native || !message.status?.running || message.status?.locked)) {
        stop(new Error("Vault locked or disconnected")); window.close();
    }
});
window.addEventListener("pagehide", () => { stopped = true; clearTimeout(timer); clearCodes(); });
load();
