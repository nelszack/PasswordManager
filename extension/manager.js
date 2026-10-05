"use strict";
const byId = id => document.getElementById(id);
let unlocked = false, selected = null, original = null, epoch = 0, searchTimer;
let fieldRows = [];
let mutationPending = false, revealSerial = 0, revealTimer, revealedValues = [];
function secretControl() { return ["secure-note", "ssh-key"].includes(byId("kind").value) ? byId("secretMultiline") : byId("password"); }
function renderSecretControl() {
    const multiline = secretControl() === byId("secretMultiline");
    byId("password").parentElement.hidden = multiline; byId("multilineLabel").hidden = !multiline;
}

function send(action, fields = {}) {
    return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({ action, ...fields }, response => {
            const error = chrome.runtime.lastError;
            if (error || !response?.success) reject(new Error(error?.message || response?.error || "Native host unavailable"));
            else resolve(response.data);
        });
    });
}
function message(text) { byId("message").textContent = text; }
function run(operation) { Promise.resolve().then(operation).catch(error => message(error.message)); }
function runMutation(operation) {
    if (mutationPending) return;
    mutationPending = true;
    run(async () => { try { await operation(); } finally { mutationPending = false; } });
}
function closeEditor() {
    clearTimeout(revealTimer); revealedValues = [];
    revealSerial++;
    selected = null; original = null; fieldRows = [];
    byId("editForm").reset(); byId("fields").replaceChildren(); byId("editor").hidden = true;
    byId("password").type = "password";
    renderSecretControl();
}
function clearSecrets() { closeEditor(); byId("master").value = ""; byId("keyPath").value = ""; byId("generated").value = ""; }
function renderStatus(status) {
    const active = status?.native && status?.running && !status?.locked;
    if (!active) { epoch++; clearSecrets(); byId("items").replaceChildren(); }
    const becameUnlocked = active && !unlocked;
    unlocked = Boolean(active);
    const label = !status?.native ? "Native host unavailable" : !status?.running ? "Server not running" : unlocked ? "Vault unlocked" : "Vault locked";
    byId("connection").textContent = label + (status?.warning ? ` · ${status.warning}` : "");
    byId("lock").disabled = !unlocked;
    byId("locked").hidden = unlocked;
    byId("unlocked").hidden = !unlocked;
    byId("unlockForm").hidden = !status?.native || !status?.running;
    if (becameUnlocked) run(loadItems);
    if (status?.native && !unlocked) run(loadVaults);
}
async function loadVaults() {
    const vaults = await send("managerVaults");
    const selection = byId("vault").value;
    byId("vault").replaceChildren(...vaults.map(filename => {
        const option = document.createElement("option"); option.value = filename; option.textContent = filename; return option;
    }));
    if (vaults.includes(selection)) byId("vault").value = selection;
    byId("master").disabled = vaults.length === 0;
    if (vaults.length === 0) message("No vaults found. Create one with pm new.");
}
async function loadItems() {
    const generation = ++epoch;
    const result = await send("managerList", { query: byId("search").value });
    if (!unlocked || generation !== epoch) return;
    byId("count").textContent = `${result.total} items${result.total > result.items.length ? " — showing the first 100; narrow your search" : ""}`;
    byId("items").replaceChildren(...result.items.map(item => {
        const button = document.createElement("button"); button.textContent = `${item.name} · ${item.username || item.kind}`;
        button.addEventListener("click", () => run(() => openItem(item.id))); return button;
    }));
}
function addField(field = { name: "", value: "", secret: false }) {
    const row = document.createElement("div"); row.className = "custom-field";
    const name = document.createElement("input"); name.value = field.name; name.required = true; name.maxLength = 4096; name.setAttribute("aria-label", "Field name");
    const value = document.createElement("input"); value.value = field.value ?? ""; value.maxLength = 65536;
    value.placeholder = field.value === null ? "Leave blank to keep the stored secret" : "Field value"; value.setAttribute("aria-label", "Field value");
    const label = document.createElement("label"), secret = document.createElement("input"); secret.type = "checkbox"; secret.checked = field.secret;
    value.type = secret.checked ? "password" : "text"; secret.addEventListener("change", () => { value.type = secret.checked ? "password" : "text"; });
    label.append(secret, document.createTextNode(" Secret"));
    const remove = document.createElement("button"); remove.type = "button"; remove.textContent = "Remove field";
    const record = { row, name, value, secret, original: field }; fieldRows.push(record);
    remove.addEventListener("click", () => { fieldRows = fieldRows.filter(f => f !== record); row.remove(); });
    row.append(name, value, label, remove); byId("fields").append(row);
}
async function openItem(id) {
    const generation = ++epoch;
    const item = await send("managerItem", { entryId: id });
    if (!unlocked || generation !== epoch) return;
    closeEditor(); selected = id; original = item;
    byId("editorTitle").textContent = item.name;
    for (const key of ["name", "kind", "username", "notes"]) byId(key).value = item[key] || "";
    renderSecretControl();
    byId("urls").value = item.urls.join("\n"); item.fields.forEach(addField);
    byId("dates").textContent = `Created: ${item.created} · Modified: ${item.modified}`;
    byId("authenticator").textContent = item.has_totp ? "TOTP configured; use the page picker or pm totp show for a current code." : "";
    byId("editor").hidden = false; byId("delete").hidden = false;
    byId("reveal").disabled = false; byId("copy").disabled = !item.has_secret;
}
byId("unlockForm").addEventListener("submit", event => {
    event.preventDefault(); const password = byId("master").value, keyPath = byId("keyPath").value; byId("master").value = ""; byId("keyPath").value = "";
    runMutation(async () => { await send("managerUnlock", { password, keyPath, vaultFile: byId("vault").value }); message("Vault unlocked."); await refresh(); });
});
byId("lock").addEventListener("click", () => run(async () => {
    epoch++; clearSecrets(); await send("lockVault"); await refresh();
}));
byId("search").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => run(loadItems), 200); });
byId("new").addEventListener("click", () => {
    epoch++; closeEditor(); byId("editorTitle").textContent = "New item"; byId("editor").hidden = false;
    byId("delete").hidden = true; byId("copy").disabled = true; byId("reveal").disabled = true;
});
byId("cancel").addEventListener("click", () => { epoch++; closeEditor(); });
byId("kind").addEventListener("change", renderSecretControl);
byId("addField").addEventListener("click", () => addField());
byId("copy").addEventListener("click", () => run(async () => { message(await send("managerCopy", { entryId: selected })); }));
byId("reveal").addEventListener("click", () => run(async () => {
    const id = selected, generation = epoch, serial = ++revealSerial;
    const item = await send("managerItem", { entryId: id, reveal: true });
    if (!unlocked || generation !== epoch || selected !== id || serial !== revealSerial) return;
    clearTimeout(revealTimer);
    revealedValues = revealedValues.filter(({ control, value }) => control.isConnected && control.value === value);
    const primary = secretControl();
    if (!primary.value) { primary.value = item.password; byId("password").type = "text"; revealedValues.push({ control: primary, value: primary.value }); }
    for (const record of fieldRows) {
        const field = item.fields.find(f => f.name === record.original.name);
        if (field?.secret && record.original.value === null && !record.value.value) {
            record.value.value = field.value; record.value.type = "text";
            revealedValues.push({ control: record.value, value: record.value.value });
        }
    }
    revealTimer = setTimeout(() => {
        if (selected !== id || serial !== revealSerial) return;
        for (const { control, value } of revealedValues) {
            if (control.value === value) { control.value = ""; if (control.tagName === "INPUT") control.type = "password"; }
        }
        revealedValues = [];
    }, 30_000);
}));
byId("editForm").addEventListener("submit", event => {
    event.preventDefault();
    runMutation(async () => {
        const fields = fieldRows.filter(f => !(f.original.value === null && !f.value.value && f.name.value === f.original.name && f.secret.checked)).map(f => ({ name: f.name.value, value: f.value.value, secret: f.secret.checked }));
        if (fieldRows.some(f => f.original.value === null && !f.value.value && (f.name.value !== f.original.name || !f.secret.checked))) throw new Error("Reveal or enter a value before renaming or changing a stored secret field.");
        const urls = byId("urls").value.split("\n").map(v => v.trim()).filter(Boolean);
        const item = { name: byId("name").value, kind: byId("kind").value, username: byId("username").value,
            password: secretControl().value || null, notes: byId("notes").value, urls, fields,
            removeUrls: (original?.urls || []).filter(url => !urls.includes(url)),
            removeFields: (original?.fields || []).filter(field => !fieldRows.some(f => f.name.value === field.name)).map(f => f.name) };
        const id = selected, generation = epoch; await send(id ? "managerUpdate" : "managerAdd", { entryId: id, item });
        if (!unlocked) return;
        if (generation === epoch && selected === id) closeEditor();
        message("Item saved."); await loadItems();
    });
});
byId("delete").addEventListener("click", () => runMutation(async () => {
    if (!confirm("Move this item to encrypted trash? Restore it later with pm restore.")) return;
    const id = selected, generation = epoch;
    await send("managerDelete", { entryId: id });
    if (!unlocked) return;
    if (generation === epoch && selected === id) closeEditor();
    message("Item moved to trash."); await loadItems();
}));
function generatorSettings() {
    return PasswordManagerGenerator.validate({ mode: byId("genMode").value, length: Number(byId("genLength").value),
        uppercase: byId("genUppercase").checked, lowercase: byId("genLowercase").checked, digits: byId("genDigits").checked,
        symbols: byId("genSymbols").checked, symbolSet: byId("genSymbolSet").value, excludeAmbiguous: byId("genAmbiguous").checked,
        words: Number(byId("genWords").value), separator: byId("genSeparator").value });
}
byId("generatorForm").addEventListener("submit", event => { event.preventDefault(); run(() => { byId("generated").value = PasswordManagerGenerator.generate(generatorSettings()); }); });
byId("generateItem").addEventListener("click", () => run(() => { secretControl().value = PasswordManagerGenerator.generate(generatorSettings()); byId("password").type = "password"; }));
byId("genSite").addEventListener("input", () => { byId("saveGenerator").textContent = byId("genSite").value ? "Save site settings" : "Save browser defaults"; });
byId("saveGenerator").addEventListener("click", () => run(async () => {
    const settings = generatorSettings();
    if (byId("genSite").value) {
        const origin = PasswordManagerGenerator.siteOrigin(byId("genSite").value);
        const stored = await chrome.storage.local.get("pmGeneratorsByOrigin");
        const overrides = { ...(stored.pmGeneratorsByOrigin || {}), [origin]: settings };
        if (Object.keys(overrides).length > 1000) throw new Error("Remove a site override before adding more than 1000 sites");
        await chrome.storage.local.set({ pmGeneratorsByOrigin: overrides }); message(`Generator settings saved for ${origin}.`);
    } else { await chrome.storage.local.set({ pmGenerator: settings }); message("Browser generator defaults saved."); }
}));
byId("removeSiteGenerator").addEventListener("click", () => run(async () => {
    const origin = PasswordManagerGenerator.siteOrigin(byId("genSite").value);
    const stored = await chrome.storage.local.get("pmGeneratorsByOrigin"), overrides = { ...(stored.pmGeneratorsByOrigin || {}) };
    delete overrides[origin]; await chrome.storage.local.set({ pmGeneratorsByOrigin: overrides }); message(`Site override removed for ${origin}.`);
}));
chrome.storage.local.get("pmGenerator", result => {
    let settings; try { settings = PasswordManagerGenerator.validate(result.pmGenerator || {}); } catch (_) { settings = PasswordManagerGenerator.defaults; }
    for (const [id, key] of [["genMode", "mode"], ["genLength", "length"], ["genWords", "words"], ["genSeparator", "separator"], ["genSymbolSet", "symbolSet"]]) byId(id).value = settings[key];
    for (const [id, key] of [["genUppercase", "uppercase"], ["genLowercase", "lowercase"], ["genDigits", "digits"], ["genSymbols", "symbols"], ["genAmbiguous", "excludeAmbiguous"]]) byId(id).checked = settings[key];
});
async function refresh() {
    const status = await new Promise(resolve => chrome.runtime.sendMessage({ action: "getStatus" }, resolve)); renderStatus(status);
}
chrome.runtime.onMessage.addListener(message => { if (message.action === "statusChanged") renderStatus(message.status); });
window.addEventListener("pagehide", clearSecrets);
run(refresh);
