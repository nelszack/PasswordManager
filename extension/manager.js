"use strict";
const PasswordManagerGenerator = require("./password_generator.js");
const PasswordManagerOperationRecovery = require("./operation_recovery.js");
const SecretReveal = require("./secret_reveal.js");
const Conflict = require("./manager_conflict.js");
module.exports.create = function create() {
    const byId = id => document.getElementById(id);
    let disposed = false;
    let sessionId = null;
    let unlocked = false, selected = null, original = null, epoch = 0, searchTimer;
    let fieldRows = [];
    let dirty = false, editRevision = 0, revealed = false;
    let mutationEditorFocus = false;
    let listedItems = [], itemPage = 0, totalItems = 0, listSerial = 0, conflicted = false, conflictLatest = null;
    const storedReveals = new WeakMap();
    const pageSize = 50;
    function markDirty() { dirty = true; editRevision++; if (!secretControl().value && selected === null) byId("reveal").disabled = true; else byId("reveal").disabled = false; }
    function mayDiscard() { if (mutations.pending) { message("Wait for the current change to finish before switching items."); return false; } return !dirty || window.confirm("Discard your unsaved item changes?"); }
    byId("editForm").addEventListener("input", markDirty);
    byId("editForm").addEventListener("change", markDirty);
    window.addEventListener("beforeunload", event => {
        if (dirty) { event.preventDefault(); event.returnValue = ""; }
    });
    let duoTimer, duoSerial = 0, duoBusy = false, duoRendered = "";

    const mutations = PasswordManagerOperationRecovery.create({
        reconcile: operationId => send("reconcileOperation", { operationId }),
        acknowledgeUnknown: operationId => send("acknowledgeUnknownOperation", { operationId, inspected: true }),
        onUncertain() { byId("acknowledgeUnknown").hidden = true; byId("reviewOutcome").hidden = false; epoch++; clearSecrets(); }
    });
    const renderedValues = new WeakMap();
    const reveal = SecretReveal.create({ onHidden() { revealed = false; byId("reveal").textContent = "Reveal for 30 seconds"; }, setTimeout: (handler, delay) => setTimeout(handler, delay), clearTimeout: timer => clearTimeout(timer), onHide: control => { renderedValues.delete(control); storedReveals.delete(control); } });
    function setStoredValue(control, value) {
        control.value = value;
        // Textareas normalize CRLF/CR to LF. Preserve stored bytes when the user
        // saves an unrelated edit without changing the displayed value.
        renderedValues.set(control, { stored: value, displayed: control.value });
    }
    function controlValue(control) {
        const rendered = renderedValues.get(control);
        return rendered && control.value === rendered.displayed ? rendered.stored : control.value;
    }
    function secretControl() { return byId("multilineLabel").hidden ? byId("password") : byId("secretMultiline"); }
    function renderSecretControl(value = controlValue(secretControl())) {
        const previous = secretControl();
        const multiline = ["secure-note", "ssh-key"].includes(byId("kind").value) || /[\r\n]/.test(value);
        const control = byId(multiline ? "secretMultiline" : "password");
        if (control !== previous) {
            const previousDisplayed = previous.value;
            setStoredValue(control, value); previous.value = ""; renderedValues.delete(previous);
            // Moving an unchanged revealed value keeps its original deadline.
            reveal.transfer(previous, control, previousDisplayed);
            if (storedReveals.get(previous) === previousDisplayed) { storedReveals.set(control, control.value); storedReveals.delete(previous); }
            byId("password").type = "password";
        } else setStoredValue(control, value);
        control.hidden = false;
        byId("password").parentElement.hidden = multiline; byId("multilineLabel").hidden = !multiline;
    }

    function send(action, fields = {}) {
        return new Promise((resolve, reject) => {
            const scoped = ["managerItem", "managerCopy", "managerAdd", "managerUpdate", "managerDelete", "managerDuoRequests", "managerDuoRespond"].includes(action);
            chrome.runtime.sendMessage({ action, ...fields, ...(scoped ? { expectedSession: sessionId } : {}) }, response => {
                const error = chrome.runtime.lastError;
                if (error || !response?.success) {
                    const failure = new Error(error?.message || response?.error || "Native host unavailable");
                    failure.uncertain = Boolean(response?.uncertain);
                    failure.operationId = response?.operationId;
                    failure.operationAction = response?.operationAction || action;
                    failure.code = response?.code;
                    reject(failure);
                }
                else resolve(response.data);
            });
        });
    }
    function message(text) { byId("message").textContent = text; }
    function run(operation) { Promise.resolve().then(operation).catch(error => message(error.message)); }
    function runMutation(operation) { run(async () => {
        if (mutations.pending) return;
        const focused = document.activeElement;
        mutationEditorFocus = Boolean(byId("editor").contains?.(focused));
        byId("editForm").inert = true;
        byId("editor").setAttribute("aria-busy", "true");
        try { await mutations.run(operation); }
        finally {
            byId("editForm").inert = false; byId("editor").setAttribute("aria-busy", "false");
            if (mutationEditorFocus && document.activeElement === document.body && !byId("editor").hidden) {
                (focused?.isConnected && !focused.disabled ? focused : byId("name")).focus();
            }
            mutationEditorFocus = false;
        }
    }); }
    window.addEventListener("keydown", event => { if (event.key === "Escape") reveal.hide(); });
    byId("reviewOutcome").addEventListener("click", () => run(async () => {
        byId("reviewOutcome").disabled = true;
        try {
            const outcome = await mutations.review();
            await refresh();
            if (unlocked && !await loadItems()) throw new Error("Vault changed during review; refresh and inspect it again.");
            byId("acknowledgeUnknown").hidden = outcome.state !== "unknown";
            byId("reviewOutcome").hidden = !mutations.unresolved;
            message(outcome.state === "committed" ? "Your change completed. The vault has been refreshed."
                : outcome.state === "committed_durability_unknown" ? "Your change committed, but storage durability is uncertain. Keep the vault open and inspect your storage."
                : outcome.state === "failed" ? "The previous operation failed. Review the refreshed vault before trying again."
                : outcome.state === "pending" ? "The previous operation is still running. Check its outcome again."
                : "The previous operation's outcome is unknown. Further changes remain blocked.");
        } finally { byId("reviewOutcome").disabled = false; }
    }));
    byId("acknowledgeUnknown").addEventListener("click", () => run(async () => {
        byId("acknowledgeUnknown").disabled = true;
        try {
            await refresh();
            const stateOnly = ["lock", "managerUnlock"].includes(mutations.unresolved?.action);
            if (!stateOnly && (!unlocked || !await loadItems())) throw new Error("Inspect the unlocked vault before allowing new changes.");
            const inspection = stateOnly ? `I inspected the lock state (currently ${unlocked ? "unlocked" : "locked"})` : "I inspected the vault";
            if (!window.confirm(`${inspection}; allow new changes. The earlier operation will not be retried.`)) return;
            await mutations.acknowledge();
            byId("acknowledgeUnknown").hidden = true; byId("reviewOutcome").hidden = true;
            message("Acknowledged. You can now make a new change; the earlier operation was not retried.");
        } finally { byId("acknowledgeUnknown").disabled = false; }
    }));
    function focusItem(id) {
        const button = Array.from(byId("items").children).find(button => button.getAttribute("data-entry-id") === String(id));
        (button || byId("new")).focus();
    }
    function closeEditor(restoreFocus = true) {
        const returnId = selected;
        const returning = restoreFocus && (byId("editor").contains?.(document.activeElement) || (mutationEditorFocus && document.activeElement === document.body));
        dirty = false; editRevision++; conflicted = false; conflictLatest = null; byId("conflict").hidden = true; byId("saveItem").disabled = false;
        stopDuo(); byId("duo").hidden = true; byId("duoRequests").replaceChildren(); duoRendered = "";
        reveal.cancel();
        for (const control of ["password", "secretMultiline", "name", "kind", "username", "notes"].map(byId).concat(fieldRows.flatMap(field => [field.name, field.value]))) renderedValues.delete(control);
        selected = null; original = null; fieldRows = [];
        byId("editForm").reset(); byId("fields").replaceChildren(); byId("editor").hidden = true;
        byId("password").type = "password";
        renderSecretControl();
        renderItems();
        if (returning) focusItem(returnId);
    }
    function clearSecrets() { listSerial++; clearTimeout(searchTimer); listedItems = []; itemPage = 0; totalItems = 0; closeEditor(false); byId("master").value = ""; byId("keyPath").value = ""; byId("generated").value = ""; byId("copyGenerated").disabled = true; byId("useGenerated").disabled = true; }
    function renderStatus(status) {
        if (disposed) return;
        const focused = document.activeElement;
        const restoreFocus = ((!status?.native || !status?.running || status?.locked || (unlocked && sessionId !== status.sessionId))
                && (byId("unlocked").contains?.(focused) || focused === byId("lock")))
            || (!unlocked && status?.native && status?.running && !status?.locked && byId("locked").contains?.(focused))
            || ((!status?.native || !status?.running) && byId("unlockForm").contains?.(focused));
        const outstanding = status?.pendingOperations?.[0];
        if (outstanding) mutations.remember(outstanding.operationId, outstanding.action);
        const active = status?.native && status?.running && !status?.locked;
        if (!active) { epoch++; clearSecrets(); byId("items").replaceChildren(); }
        const sessionChanged = active && unlocked && sessionId !== status.sessionId;
        if (sessionChanged) { epoch++; clearSecrets(); byId("items").replaceChildren(); }
        const becameUnlocked = active && (!unlocked || sessionChanged);
        sessionId = active ? status.sessionId : null;
        unlocked = Boolean(active);
        byId("setup").textContent = !status?.native
            ? "Connect the browser bridge using the steps below, then check the connection again."
            : !status?.running ? "Run pm start in a terminal, then check the connection again."
            : "Choose a vault and enter its master password or an absolute key-file path.";
        byId("connectionHelp").open = !status?.native || !status?.running;
        const label = !status?.native ? "Native host unavailable" : !status?.running ? "Server not running" : unlocked ? "Vault unlocked" : "Vault locked";
        byId("connection").textContent = label + (status?.warning ? ` · ${status.warning}` : "");
        byId("lock").disabled = !unlocked;
        byId("locked").hidden = unlocked;
        byId("unlocked").hidden = !unlocked;
        byId("unlockForm").hidden = !status?.native || !status?.running;
        if (restoreFocus) {
            (unlocked ? byId("search") : !status?.native || !status?.running ? byId("retryConnection")
                : byId("master").disabled ? byId("keyPath") : byId("master")).focus();
        }
        if (becameUnlocked) run(loadItems);
        if (status?.native && !unlocked) run(loadVaults);
    }
    async function loadVaults() {
        const vaults = await send("managerVaults");
        if (disposed) return;
        const selection = byId("vault").value;
        byId("vault").replaceChildren(...vaults.map(filename => {
            const option = document.createElement("option"); option.value = filename; option.textContent = filename; return option;
        }));
        if (vaults.includes(selection)) byId("vault").value = selection;
        byId("master").disabled = vaults.length === 0;
        if (vaults.length === 0) message("No vaults found. Create one with pm new.");
    }
    async function loadItems(requestedPage = itemPage) {
        const generation = ++listSerial, session = sessionId;
        let result;
        try { result = await send("managerList", { query: byId("search").value, offset: requestedPage * pageSize, limit: pageSize }); }
        catch (error) { if (unlocked && generation === listSerial && session === sessionId) renderItems(); throw error; }
        if (!unlocked || generation !== listSerial || session !== sessionId) return false;
        const pages = Math.max(1, Math.ceil(result.total / pageSize));
        if (requestedPage >= pages) return loadItems(pages - 1);
        itemPage = requestedPage;
        totalItems = result.total;
        listedItems = result.items;
        renderItems();
        return true;
    }
    function renderItems() {
        const focusId = document.activeElement?.getAttribute?.("data-entry-id");
        const pages = Math.max(1, Math.ceil(totalItems / pageSize));
        itemPage = Math.max(0, Math.min(itemPage, pages - 1));
        byId("count").textContent = pages === 1 ? `${totalItems} items` : `${totalItems} items · page ${itemPage + 1} of ${pages}`;
        byId("itemPages").hidden = pages === 1;
        byId("itemPage").max = pages; byId("itemPage").value = itemPage + 1;
        byId("previousItems").disabled = itemPage === 0;
        byId("nextItems").disabled = itemPage + 1 === pages;
        byId("items").replaceChildren(...listedItems.map(item => {
            const button = document.createElement("button"); button.textContent = `${item.name} · ${item.username || item.kind}`;
            button.setAttribute("aria-pressed", String(item.id === selected));
            button.setAttribute("data-entry-id", String(item.id));
            button.addEventListener("click", () => run(() => openItem(item.id))); return button;
        }));
        if (focusId) focusItem(focusId);
    }
    byId("previousItems").addEventListener("click", () => run(() => loadItems(Math.max(0, itemPage - 1))));
    byId("nextItems").addEventListener("click", () => run(() => loadItems(itemPage + 1)));
    byId("itemPage").addEventListener("change", () => { const page = Number(byId("itemPage").value); run(() => loadItems(Number.isInteger(page) && page > 0 ? Math.min(page - 1, Math.max(0, Math.ceil(totalItems / pageSize) - 1)) : itemPage)); });
    byId("refreshItems").addEventListener("click", () => run(async () => { if (await loadItems()) message("Item list refreshed. Your editor changes are preserved."); }));
    function addField(field = { name: "", value: "", secret: false }) {
        const row = document.createElement("div"); row.className = "custom-field";
        const name = document.createElement("input"); setStoredValue(name, field.name); name.required = true; name.maxLength = 4096; name.setAttribute("aria-label", "Field name");
        const value = document.createElement(/[\r\n]/.test(field.value || "") ? "textarea" : "input"); setStoredValue(value, field.value ?? ""); value.maxLength = 65536;
        value.placeholder = field.value === null ? "Leave blank to keep the stored secret" : "Field value"; value.setAttribute("aria-label", "Field value");
        const label = document.createElement("label"), secret = document.createElement("input"); secret.type = "checkbox"; secret.checked = field.secret;
        if (value.tagName === "INPUT") value.type = secret.checked ? "password" : "text";
        label.append(secret, document.createTextNode(" Secret"));
        const remove = document.createElement("button"); remove.type = "button"; remove.textContent = "Remove field";
        const record = { row, name, value, secret, original: field }; fieldRows.push(record);
        secret.addEventListener("change", () => { if (record.value.tagName === "INPUT") record.value.type = secret.checked ? "password" : "text"; markDirty(); });
        remove.addEventListener("click", () => {
            const index = fieldRows.indexOf(record);
            fieldRows = fieldRows.filter(f => f !== record); row.remove(); markDirty();
            (fieldRows[index]?.name || fieldRows[index - 1]?.name || byId("addField")).focus();
        });
        row.append(name, value, label, remove); byId("fields").append(row);
    }
    async function openItem(id) {
        if (!mayDiscard()) return;
        const revision = editRevision;
        const generation = ++epoch;
        const item = await send("managerItem", { entryId: id });
        if (!unlocked || generation !== epoch) return;
        if (revision !== editRevision && !mayDiscard()) return;
        closeEditor(false); selected = id; original = item; renderItems();
        byId("editorTitle").textContent = item.name;
        for (const key of ["name", "kind", "username", "notes"]) setStoredValue(byId(key), item[key] || "");
        renderSecretControl();
        byId("urls").value = item.urls.join("\n"); item.fields.forEach(addField);
        byId("dates").textContent = `Created: ${item.created} · Modified: ${item.modified}`;
        byId("authenticator").textContent = item.has_totp ? "Authenticator configured; use the page picker or pm totp show for a code. HOTP requests advance its counter." : "";
        byId("editor").hidden = false; byId("delete").hidden = false;
        byId("duo").hidden = !item.has_duo; byId("duoStatus").textContent = item.has_duo ? "Check requests or enable monitoring. Monitoring stops when the vault locks." : "";
        byId("reveal").disabled = false; byId("copy").disabled = !item.has_secret;
        byId("name").focus();
    }
    byId("unlockForm").addEventListener("submit", event => {
        event.preventDefault(); const password = byId("master").value, keyPath = byId("keyPath").value; byId("master").value = ""; byId("keyPath").value = "";
        runMutation(async () => { await send("managerUnlock", { ...(password ? { password } : {}), ...(keyPath ? { keyPath } : {}), ...(byId("vault").value ? { vaultFile: byId("vault").value } : {}) }); message("Vault unlocked."); await refresh(); });
    });
    byId("lock").addEventListener("click", () => run(async () => {
        epoch++; clearSecrets(); await send("lockVault"); await refresh();
    }));
    byId("search").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => run(() => loadItems(0)), 200); });
    byId("new").addEventListener("click", () => {
        if (!mayDiscard()) return;
        epoch++; closeEditor(); byId("editorTitle").textContent = "New item"; byId("editor").hidden = false;
        byId("delete").hidden = true; byId("copy").disabled = true; byId("reveal").disabled = true;
        byId("name").focus();
    });
    byId("cancel").addEventListener("click", () => { if (mayDiscard()) { epoch++; closeEditor(); } });
    byId("kind").addEventListener("change", () => renderSecretControl());
    byId("addField").addEventListener("click", () => { addField(); markDirty(); fieldRows.at(-1).name.focus(); });
    byId("copy").addEventListener("click", () => run(async () => { message(await send("managerCopy", { entryId: selected })); }));
    byId("reveal").addEventListener("click", () => run(async () => {
        if (revealed) { reveal.hide(); return; }
        const id = selected, generation = epoch, serial = reveal.request();
        const item = id === null ? { fields: [] } : await send("managerItem", { entryId: id, reveal: true });
        if (!unlocked || generation !== epoch || selected !== id || serial !== reveal.serial) return;
        reveal.retainCurrent();
        const loaded = !secretControl().value;
        if (loaded) renderSecretControl(item.password || "");
        const primary = secretControl(); primary.hidden = false;
        byId("password").type = "text";
        reveal.track(primary, loaded);
        if (loaded) storedReveals.set(primary, primary.value);
        for (const record of fieldRows) {
            const field = item.fields.find(f => f.name === record.original.name);
            if (field?.secret && record.original.value === null && !record.value.value) {
                if (/[\r\n]/.test(field.value) && record.value.tagName !== "TEXTAREA") {
                    const multiline = document.createElement("textarea");
                    multiline.maxLength = record.value.maxLength; multiline.placeholder = record.value.placeholder;
                    multiline.setAttribute("aria-label", "Field value");
                    record.value.replaceWith(multiline); renderedValues.delete(record.value); record.value = multiline;
                }
                setStoredValue(record.value, field.value); storedReveals.set(record.value, record.value.value);
                reveal.track(record.value);
            } else if (record.secret.checked && record.value.value) reveal.track(record.value, false);
            if (record.secret.checked) { record.value.hidden = false; if (record.value.tagName === "INPUT") record.value.type = "text"; }
        }
        revealed = true; byId("reveal").textContent = "Hide now (Esc)";
        reveal.schedule(() => selected === id, serial);
    }));
    function editValue() {
            const fields = fieldRows.filter(f => !(f.original.value === null && !f.value.value && controlValue(f.name) === f.original.name && f.secret.checked)).map(f => ({ name: controlValue(f.name), value: controlValue(f.value), secret: f.secret.checked }));
            if (fieldRows.some(f => f.original.value === null && !f.value.value && (controlValue(f.name) !== f.original.name || !f.secret.checked))) throw new Error("Reveal or enter a value before renaming or changing a stored secret field.");
            const urls = byId("urls").value.split("\n").map(v => v.trim()).filter(Boolean);
            return { name: controlValue(byId("name")), kind: byId("kind").value, username: controlValue(byId("username")),
                password: controlValue(secretControl()) || null, notes: controlValue(byId("notes")), urls, fields,
                removeUrls: (original?.urls || []).filter(url => !urls.includes(url)),
                removeFields: (original?.fields || []).filter(field => !fieldRows.some(f => controlValue(f.name) === field.name)).map(f => f.name) };
    }
    function localConflictValue() {
        const local = editValue();
        if (storedReveals.get(secretControl()) === secretControl().value) local.password = null;
        local.fields = local.fields.filter(field => {
            const record = fieldRows.find(row => controlValue(row.name) === field.name);
            return !record || storedReveals.get(record.value) !== record.value.value || controlValue(record.name) !== record.original.name || record.secret.checked !== record.original.secret;
        });
        return local;
    }
    byId("reviewConflict").addEventListener("click", () => run(async () => {
        const id = selected, generation = epoch;
        const latest = await send("managerItem", {entryId:id});
        if (!unlocked || generation !== epoch || id !== selected || !conflicted) return;
        conflictLatest = latest;
        byId("conflictDiff").textContent = Conflict.summary(original, latest, localConflictValue());
        byId("reapplyConflict").hidden = false;
    }));
    byId("reapplyConflict").addEventListener("click", () => run(() => {
        if (!conflicted || !conflictLatest || mutations.pending) return;
        const merged = Conflict.rebase(original, conflictLatest, localConflictValue());
        reveal.cancel();
        for (const key of ["name", "kind", "username", "notes"]) setStoredValue(byId(key), merged[key] || "");
        renderSecretControl(merged.password || ""); byId("password").type = "password";
        byId("urls").value = (merged.urls || []).join("\n");
        fieldRows = []; byId("fields").replaceChildren(); merged.fields.forEach(addField);
        original = conflictLatest; conflictLatest = null; conflicted = false;
        byId("conflict").hidden = true; byId("saveItem").disabled = false; markDirty();
        message("Edits reapplied to the reviewed revision. Review the draft and Save item; nothing was saved automatically.");
        byId("name").focus();
    }));
    byId("editForm").addEventListener("submit", event => {
        event.preventDefault();
        runMutation(async () => {
            if (conflicted) throw new Error("Review the latest version and reapply your edits before saving.");
            const item = editValue();
            const id = selected, generation = epoch;
            try { await send(id ? "managerUpdate" : "managerAdd", { ...(id ? { entryId: id, expectedRevision: original.revision } : {}), item }); }
            catch (error) {
                if (id === selected && generation === epoch && (error.code === 4 || /revision|conflict|changed since/i.test(error.message))) {
                    conflicted = true; conflictLatest = null;
                    byId("conflict").hidden = false; byId("reapplyConflict").hidden = true; byId("saveItem").disabled = true;
                }
                throw error;
            }
            if (!unlocked) return;
            if (generation === epoch && selected === id) closeEditor();
            message("Item saved."); await loadItems();
        });
    });
    byId("delete").addEventListener("click", () => runMutation(async () => {
        if (!confirm("Move this item to encrypted trash? Restore it later with pm restore.")) return;
        const id = selected, generation = epoch;
        await send("managerDelete", { entryId: id, expectedRevision: original.revision });
        if (!unlocked) return;
        if (generation === epoch && selected === id) closeEditor();
        message("Item moved to trash."); await loadItems();
    }));
    function generatorSettings() {
        const passphrase = byId("genMode").value === "passphrase";
        const defaults = PasswordManagerGenerator.defaults;
        const length = Number(byId("genLength").value), words = Number(byId("genWords").value);
        const symbolSet = byId("genSymbolSet").value, separator = byId("genSeparator").value;
        return PasswordManagerGenerator.validate({ mode: byId("genMode").value,
            length: passphrase && (!Number.isInteger(length) || length < 1 || length > 255) ? defaults.length : length,
            uppercase: byId("genUppercase").checked, lowercase: byId("genLowercase").checked, digits: byId("genDigits").checked,
            symbols: byId("genSymbols").checked,
            symbolSet: passphrase && (symbolSet.length > 128 || /[^\x21-\x7e]/.test(symbolSet)) ? defaults.symbolSet : symbolSet,
            excludeAmbiguous: byId("genAmbiguous").checked,
            words: !passphrase && (!Number.isInteger(words) || words < 1 || words > 32) ? defaults.words : words,
            separator: !passphrase && (separator.length > 16 || /[\x00-\x1f\x7f]/.test(separator)) ? defaults.separator : separator });
    }
    function updateGeneratorMode() {
        const passphrase = byId("genMode").value === "passphrase";
        byId("passwordOptions").hidden = passphrase;
        byId("passwordOptions").disabled = passphrase;
        byId("passphraseOptions").hidden = !passphrase;
        byId("passphraseOptions").disabled = !passphrase;
    }
    byId("genMode").addEventListener("change", updateGeneratorMode);
    function registrationCommand() {
        byId("installCommand").value = `pm native-host install --extension-id ${chrome.runtime.id || "YOUR_EXTENSION_ID"} --browser ${byId("setupBrowser").value || "chrome"}`;
    }
    registrationCommand();
    byId("setupBrowser").addEventListener("change", registrationCommand);
    byId("copyInstallCommand").addEventListener("click", () => run(async () => {
        await navigator.clipboard.writeText(byId("installCommand").value);
        message("Registration command copied. Run it in a terminal, then reload the extension.");
    }));
    byId("retryConnection").addEventListener("click", () => run(refresh));
    byId("useGenerated").addEventListener("click", () => {
        if (!unlocked || !byId("generated").value || mutations.pending) return;
        if (byId("editor").hidden) {
            epoch++; closeEditor(); byId("editorTitle").textContent = "New item";
            byId("editor").hidden = false; byId("delete").hidden = true;
            byId("copy").disabled = true; byId("reveal").disabled = true;
        } else if (!window.confirm("Replace the primary secret in this draft with the generated value? Other edits will be kept.")) return;
        renderSecretControl(byId("generated").value); byId("password").type = "password"; markDirty();
        byId("name").focus(); message("Generated value added to the draft. Save the item to keep it.");
    });
    byId("copyGenerated").addEventListener("click", () => run(async () => {
        if (!byId("generated").value) throw new Error("Generate a value before copying.");
        await navigator.clipboard.writeText(byId("generated").value);
        message("Generated value copied. Clear your clipboard after use.");
    }));
    byId("generatorForm").addEventListener("submit", event => { event.preventDefault(); run(() => { byId("generated").value = PasswordManagerGenerator.generate(generatorSettings()); byId("copyGenerated").disabled = false; byId("useGenerated").disabled = !unlocked; }); });
    byId("generateItem").addEventListener("click", () => run(() => { renderSecretControl(PasswordManagerGenerator.generate(generatorSettings())); byId("password").type = "password"; markDirty(); }));
    byId("genSite").addEventListener("input", () => { byId("saveGenerator").textContent = byId("genSite").value ? "Save site settings" : "Save browser defaults"; });
    byId("saveGenerator").addEventListener("click", () => run(async () => {
        const settings = generatorSettings();
        if (byId("genSite").value) {
            const origin = PasswordManagerGenerator.siteOrigin(byId("genSite").value);
            byId("genSite").value = origin;
            const stored = await chrome.storage.local.get("pmGeneratorsByOrigin");
            const overrides = { ...(stored.pmGeneratorsByOrigin || {}), [origin]: settings };
            if (Object.keys(overrides).length > 1000) throw new Error("Remove a site override before adding more than 1000 sites");
            await chrome.storage.local.set({ pmGeneratorsByOrigin: overrides }); message(`Generator settings saved for ${origin}.`); refreshSavedSites();
        } else { await chrome.storage.local.set({ pmGenerator: settings }); message("Browser generator defaults saved."); }
    }));
    byId("removeSiteGenerator").addEventListener("click", () => run(async () => {
        const origin = PasswordManagerGenerator.siteOrigin(byId("genSite").value);
        const stored = await chrome.storage.local.get("pmGeneratorsByOrigin"), overrides = { ...(stored.pmGeneratorsByOrigin || {}) };
        delete overrides[origin]; await chrome.storage.local.set({ pmGeneratorsByOrigin: overrides }); message(`Site override removed for ${origin}.`); refreshSavedSites();
    }));
    function applyGeneratorSettings(settings) {
        for (const [id, key] of [["genMode", "mode"], ["genLength", "length"], ["genWords", "words"], ["genSeparator", "separator"], ["genSymbolSet", "symbolSet"]]) byId(id).value = settings[key];
        for (const [id, key] of [["genUppercase", "uppercase"], ["genLowercase", "lowercase"], ["genDigits", "digits"], ["genSymbols", "symbols"], ["genAmbiguous", "excludeAmbiguous"]]) byId(id).checked = settings[key];
        updateGeneratorMode();
    }
    function refreshSavedSites() {
        chrome.storage.local.get("pmGeneratorsByOrigin", stored => {
            if (disposed) return;
            const option = document.createElement("option"); option.value = ""; option.textContent = "Browser defaults";
            const sites = Object.keys(stored.pmGeneratorsByOrigin || {}).sort().map(origin => {
                const option = document.createElement("option"); option.value = origin; option.textContent = origin; return option;
            });
            byId("savedSite").replaceChildren(option, ...sites);
            byId("savedSite").value = byId("genSite").value || "";
        });
    }
    function loadGeneratorSettings() {
        const origin = byId("genSite").value ? PasswordManagerGenerator.siteOrigin(byId("genSite").value) : "";
        chrome.storage.local.get(["pmGenerator", "pmGeneratorsByOrigin"], stored => run(() => {
            const override = origin && stored.pmGeneratorsByOrigin?.[origin];
            applyGeneratorSettings(PasswordManagerGenerator.validate(override || stored.pmGenerator || {}));
            message(override ? `Loaded saved override for ${origin}.` : origin ? `No override for ${origin}; showing inherited browser defaults.` : "Loaded browser generator defaults.");
        }));
    }
    byId("loadGeneratorSettings").addEventListener("click", () => run(loadGeneratorSettings));
    byId("savedSite").addEventListener("change", () => { byId("genSite").value = byId("savedSite").value; byId("saveGenerator").textContent = byId("genSite").value ? "Save site settings" : "Save browser defaults"; run(loadGeneratorSettings); });
    chrome.storage.local.get("pmGenerator", result => {
        let settings; try { settings = PasswordManagerGenerator.validate(result.pmGenerator || {}); } catch (_) { settings = PasswordManagerGenerator.defaults; }
        applyGeneratorSettings(settings); refreshSavedSites();
    });

    function stopDuo() {
        clearTimeout(duoTimer); duoSerial++;
        byId("duoWatch").checked = false;
        for (const input of byId("duoRequests").querySelectorAll("input")) input.value = "";
    }
    function duoCurrent(id, serial) { return unlocked && selected === id && original?.has_duo && serial === duoSerial; }
    async function checkDuo() {
        if (duoBusy || !unlocked || !selected || !original?.has_duo) return;
        const id = selected, serial = duoSerial; duoBusy = true;
        byId("duoCheck").disabled = true;
        try {
            const requests = await send("managerDuoRequests", { entryId: id });
            if (!duoCurrent(id, serial)) return;
            if (!Array.isArray(requests)) throw new Error("Invalid Duo request response");
            byId("duoStatus").textContent = requests.length ? `${requests.length} pending request(s).` : "No pending requests.";
            const key = JSON.stringify(requests.map(r => [r.id, r.fingerprint]));
            if (key !== duoRendered) {
                for (const input of byId("duoRequests").querySelectorAll("input")) input.value = "";
                byId("duoRequests").replaceChildren(...requests.map(r => duoRequest(r, id, serial)));
                duoRendered = key;
            }
        } catch (error) {
            if (duoCurrent(id, serial)) {
                stopDuo(); byId("duoRequests").replaceChildren(); duoRendered = "";
                byId("duoStatus").textContent = error.message;
            }
        } finally {
            duoBusy = false; byId("duoCheck").disabled = false;
            if (byId("duoWatch").checked && unlocked && original?.has_duo) duoTimer = setTimeout(() => run(checkDuo), 5000);
        }
    }
    function duoRequest(r, id, serial) {
        const row = document.createElement("article"); row.className = "duo-request";
        for (const [label, value] of [["Application", r.application], ["Account", r.username], ["Location", r.location], ["Summary", r.summary], ["Request", r.id], ["Expires", new Date(r.expires_at * 1000).toLocaleString()]]) {
            const p = document.createElement("p"); p.textContent = `${label}: ${value || "Not provided"}`; row.append(p);
        }
        let code;
        if (r.code_digits) {
            const label = document.createElement("label"); label.textContent = `${r.code_digits}-digit verification code shown on the login page`;
            code = document.createElement("input"); code.type = "password"; code.inputMode = "numeric";
            code.autocomplete = "off"; code.maxLength = r.code_digits; label.append(code); row.append(label);
        }
        if (r.unsupported) { const p = document.createElement("p"); p.textContent = r.unsupported; row.append(p); }
        const actions = document.createElement("div"); actions.className = "actions";
        for (const approve of [true, false]) {
            const button = document.createElement("button"); button.type = "button"; button.textContent = approve ? "Approve login" : "Deny login";
            button.disabled = approve && Boolean(r.unsupported);
            button.addEventListener("click", event => {
                if (!event.isTrusted) return;
                runMutation(async () => {
                if (!duoCurrent(id, serial) || !row.isConnected) return;
                if (r.expires_at * 1000 <= Date.now()) throw new Error("Request expired. Check requests again.");
                if (approve && code && !new RegExp(`^[0-9]{${r.code_digits}}$`).test(code.value)) throw new Error("Enter the verification code shown on the login page.");
                const action = approve ? "Approve" : "Deny";
                if (!window.confirm(`${action} this login for ${r.application || "unknown application"}, account ${r.username || "unknown account"}, location ${r.location || "unknown location"}?`)) return;
                if (!duoCurrent(id, serial) || !row.isConnected) return;
                const verificationCode = approve ? code?.value || "" : "";
                if (code) code.value = "";
                for (const control of row.querySelectorAll("button,input")) control.disabled = true;
                try {
                    const result = await send("managerDuoRespond", { entryId: id, requestId: r.id, fingerprint: r.fingerprint, approve, verificationCode });
                    if (duoCurrent(id, serial)) { message(result); duoRendered = ""; await checkDuo(); }
                } catch (error) {
                    if (duoCurrent(id, serial)) { stopDuo(); byId("duoRequests").replaceChildren(); duoRendered = ""; }
                    throw error;
                }
                });
            });
            actions.append(button);
        }
        row.append(actions); return row;
    }
    byId("duoCheck").addEventListener("click", () => run(checkDuo));
    byId("duoWatch").addEventListener("change", () => {
        clearTimeout(duoTimer);
        if (byId("duoWatch").checked) run(checkDuo);
    });

    async function refresh() {
        const status = await new Promise(resolve => chrome.runtime.sendMessage({ action: "getStatus" }, resolve)); renderStatus(status);
        if (!status?.native || !status?.running) throw new Error("Vault status is unavailable. Reconnect before reviewing the operation.");
    }
    const statusChanged = message => { if (message.action === "statusChanged") renderStatus(message.status); };
    chrome.runtime.onMessage.addListener(statusChanged);
    window.addEventListener("pagehide", dispose);
    window.addEventListener("pm-worker-disconnected", () => {
        epoch++; renderStatus({ native: false, running: false, locked: true });
    });
    function dispose() {
        if (disposed) return;
        disposed = true; epoch++; unlocked = false;
        clearTimeout(searchTimer); clearSecrets();
        chrome.runtime.onMessage.removeListener?.(statusChanged);
    }
    run(refresh);

    return { openItem, secretControl, controlValue, checkDuo, runMutation, send,
        get fieldRows() { return fieldRows; }, get renderedValues() { return renderedValues; },
        dispose };
};
