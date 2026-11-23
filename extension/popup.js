let pendingOperations = [];
let reviewedOperationId = null;
let lastStatus = null;
let site = { items: [] };
let siteRequest = 0;
let searchRequest = 0;
let localCopyArmed = 0;
const sendMessage = PasswordManagerUiTransport.send;
const element = id => document.getElementById(id);
const State = PasswordManagerPopupState;

function say(text, error = false) {
    const output = element("output");
    output.innerText = text;
    output.className = error ? "error" : "";
}

function renderStatus(status) {
    const lockButton = element("lockBtn");
    const wasUnlocked = lastStatus && State.usable(lastStatus);
    lastStatus = status;

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
                option.textContent = State.operationLabel(record);
                return option;
            })
        );
        if (operations.some(record => record.operationId === previous)) select.value = previous;
        if (select.value !== previous) resetReview();
    }
    const presentation = State.presentation(status);
    element("statusDot").className = `dot ${presentation.tone}`;
    element("statusText").innerText = presentation.text;
    lockButton.disabled = !presentation.canLock;
    element("nativeHint").textContent = State.hint(status);
    element("nativeHint").hidden = !element("nativeHint").textContent;
    element("openDesktopBtn").textContent = State.desktopLabel(status);
    const unlocked = State.usable(status);
    // Once connected and unlocked, the site's logins are the main content.
    element("openDesktopBtn").className = unlocked ? "" : "primary";
    const setup = element("setupCard");
    if (setup) setup.hidden = Boolean(status.native) || Boolean(status.transportError);
    const section = element("siteSection");
    if (section) {
        section.hidden = !unlocked;
        if (unlocked && !wasUnlocked) loadSite();
        if (!unlocked) {
            site = { items: [] };
            // Results still in flight belong to the session that just ended.
            siteRequest++;
            searchRequest++;
            if (wasUnlocked && clearAddDraft()) say("The unsaved login was cleared because the vault locked.");
        }
    }
    const vaultSearch = element("vaultSearch");
    if (vaultSearch) {
        vaultSearch.hidden = !unlocked;
        if (!unlocked) {
            element("vaultResults").replaceChildren();
            element("vaultEmpty").hidden = true;
        }
    }
    // Unlocked, the site's logins come first; the desktop and lock buttons follow
    // them. The DOM moves too, so keyboard and screen-reader order match the screen.
    const actions = document.querySelector?.(".actions");
    const anchor = unlocked ? element("vaultSearch") : element("setupCard");
    if (actions && anchor?.parentNode?.insertBefore && anchor.nextSibling !== actions)
        anchor.parentNode.insertBefore(actions, anchor.nextSibling);
    const reconnect = element("reconnectBtn");
    if (reconnect) reconnect.hidden = !status.transportError;
    clearTimeout(reconnectTimer);
    if (!status.transportError) reconnectAttempts = 0;
    // Retry while the popup is on screen, for about a minute; Reconnect stays available.
    else if (document.visibilityState === "visible" && reconnectAttempts < 30) {
        reconnectAttempts++;
        reconnectTimer = setTimeout(refreshStatus, 2000);
    }
}
let reconnectTimer = null;
let reconnectAttempts = 0;
element("reconnectBtn")?.addEventListener("click", async () => {
    say("Reconnecting…");
    await refreshStatus();
    if (lastStatus && !lastStatus.transportError) say("Reconnected.");
});

/** Hides the Add form and erases its values; returns whether it held anything. */
function clearAddDraft() {
    const form = element("addForm");
    if (!form) return false;
    const had =
        !form.hidden &&
        Boolean(element("addUsername").value || element("addOwnPassword")?.value || element("addName").value);
    element("addName").value = "";
    element("addUsername").value = "";
    element("addPassword").textContent = "";
    if (element("addOwnPassword")) element("addOwnPassword").value = "";
    form.hidden = true;
    element("addLoginBtn").setAttribute("aria-expanded", "false");
    return had;
}

async function refreshStatus() {
    const status = await sendMessage({ action: "getStatus" });
    if (!status) return;
    // A transport failure is not the same as a missing native host.
    if (status.success === false && !("native" in status)) {
        // A failed check is authoritative: actions stay off until a fresh status arrives.
        renderStatus({ ...(lastStatus || {}), transportError: status.error || true });
        return;
    }
    renderStatus(status);
}

chrome.runtime.onMessage.addListener(message => {
    if (message.action === "statusChanged" && message.status) {
        renderStatus(message.status);
    }
});

// --- Logins for the active tab -------------------------------------------------

async function loadSite() {
    const request = ++siteRequest;
    const response = await sendMessage({ action: "popupLogins" });
    if (request !== siteRequest) return;
    site = response?.success ? response : { items: [], error: response?.error || "Could not load logins" };
    renderSite();
}

function actionButton(label, accessibleName, onClick, primary = false) {
    const button = document.createElement("button");
    button.textContent = label;
    button.className = primary ? "primary" : "";
    button.setAttribute("aria-label", accessibleName);
    button.addEventListener("click", () => onClick(button));
    return button;
}

async function copyValue(item, field, label, button) {
    const response = await sendMessage({ action: "popupCopy", id: item.id, field });
    if (response?.success) {
        say(response.data || `${label} copied.`);
        if (button) flash(button);
    } else say(response?.error || `Could not copy the ${label.toLowerCase()}.`, true);
}

async function fillLogin(item) {
    say(`Filling ${item.name}…`);
    const response = await sendMessage({ action: "popupFill", id: item.id });
    if (response?.success) {
        window.close?.();
        say(`Filled ${item.name}.`);
    } else say(response?.error || "Could not fill this page.", true);
}

/** Briefly confirms on the clicked button itself, so feedback is where you look. */
function flash(button, text = "Copied ✓") {
    const original = button.textContent;
    button.textContent = text;
    setTimeout(() => {
        button.textContent = original;
    }, 1500);
}

function loginRow(item) {
    const row = document.createElement("li");
    const who = document.createElement("div");
    who.className = "who";
    const name = document.createElement("strong");
    name.textContent = item.name || "Untitled login";
    name.title = item.name || "";
    who.append(name);
    if (item.username) {
        const username = document.createElement("span");
        username.textContent = item.username;
        username.title = item.username;
        who.append(username);
    }
    const buttons = document.createElement("div");
    buttons.className = "buttons";
    buttons.append(actionButton("Fill", `Fill ${item.name} on this page`, () => fillLogin(item), true));
    if (item.username)
        buttons.append(
            actionButton("Copy username", `Copy username for ${item.name}`, button =>
                copyValue(item, "username", "Username", button)
            )
        );
    buttons.append(
        actionButton("Copy password", `Copy password for ${item.name}`, button =>
            copyValue(item, "password", "Password", button)
        )
    );
    if (item.hasTotp)
        buttons.append(
            actionButton("Copy code", `Copy one-time code for ${item.name}`, button =>
                copyValue(item, "totp", "One-time code", button)
            )
        );
    row.append(who, buttons);
    return row;
}

function renderSite() {
    const list = element("siteList");
    const search = element("siteSearch");
    if (!list) return;
    const host = site.site ? State.hostOf(site.site) : null;
    element("siteTitle").textContent = host ? `Logins for ${host}` : "Logins for this site";
    element("addLoginBtn").hidden = !site.site;
    // Search helps once a site has several accounts.
    search.hidden = (site.items || []).length < 4;
    const shown = State.filterLogins(site.items || [], search.hidden ? "" : search.value || "");
    list.replaceChildren(...shown.map(loginRow));
    const empty = element("siteEmpty");
    empty.textContent =
        site.items?.length && !shown.length ? "No logins match your search." : State.siteMessage(site);
    empty.hidden = !empty.textContent;
}
element("siteSearch")?.addEventListener("input", renderSite);

// Adding a login uses a generated password; typing an existing one belongs to the
// site's own form, where the save prompt captures it.
function showAddForm(open) {
    element("addForm").hidden = !open;
    element("addLoginBtn").setAttribute("aria-expanded", String(open));
    if (!open) {
        // Keyboard focus returns to the button that opened the form.
        element("addPassword").textContent = "";
        if (!element("addLoginBtn").hidden) element("addLoginBtn").focus();
        return;
    }
    element("addName").value = site.site ? State.hostOf(site.site) : "";
    element("addUsername").value = "";
    element("addPassword").textContent = PasswordManagerGenerator.generate(currentGenerator());
    if (element("addOwn")) {
        element("addOwn").checked = false;
        element("addOwnPassword").value = "";
        element("addOwnRow").hidden = true;
        element("addGeneratedRow").hidden = false;
    }
    element("addName").focus();
}
element("addOwn")?.addEventListener("change", event => {
    const own = event.target.checked;
    element("addOwnRow").hidden = !own;
    element("addGeneratedRow").hidden = own;
    if (own) element("addOwnPassword").focus();
});
element("addLoginBtn")?.addEventListener("click", () => showAddForm(element("addForm").hidden));
element("addCancel")?.addEventListener("click", () => showAddForm(false));
element("addRegenerate")?.addEventListener("click", () => {
    element("addPassword").textContent = PasswordManagerGenerator.generate(currentGenerator());
});
element("addForm")?.addEventListener("submit", async event => {
    event.preventDefault();
    const name = element("addName").value.trim();
    if (!name) {
        say("Enter a name for the login.", true);
        element("addName").focus();
        return;
    }
    const own = element("addOwn")?.checked === true;
    const password = own ? element("addOwnPassword").value : element("addPassword").textContent;
    if (!password) {
        say("Enter the password for this login.", true);
        element("addOwnPassword")?.focus();
        return;
    }
    element("addSave").disabled = true;
    const response = await sendMessage({
        action: "popupSave",
        name,
        username: element("addUsername").value,
        password,
    });
    if (element("addOwnPassword")) element("addOwnPassword").value = "";
    if (response?.uncertain) {
        // The save may have completed: never offer to repeat it before review.
        say(
            "The save may have completed. Check its outcome under “A previous change needs review” before trying again.",
            true
        );
        showAddForm(false);
        element("addSave").disabled = false;
        await refreshStatus();
        return;
    }
    element("addSave").disabled = false;
    if (response?.success) {
        say(
            own
                ? `Saved ${name}.`
                : `Saved ${name}. Use “Copy password” to paste it into the site's sign-up form.`
        );
        showAddForm(false);
        await loadSite();
    } else say(response?.error || "Could not save the login.", true);
});

// --- Search all items -----------------------------------------------------------

/** "Card number" → "card number"; "API key" and "Wi-Fi password" keep their capitals. */
function lowerFirst(text) {
    return /^[A-Z][a-z]+(\s|$)/.test(text) ? text[0].toLowerCase() + text.slice(1) : text;
}

function resultRow(item) {
    const profile = globalThis.PasswordManagerCommandContract?.itemProfiles?.[item.kind] || {
        title: "Login",
        owner: "Username",
        secret: "Password",
    };
    const row = document.createElement("li");
    const who = document.createElement("div");
    who.className = "who";
    const name = document.createElement("strong");
    name.textContent = item.name || "Untitled item";
    name.title = item.name || "";
    const detail = document.createElement("span");
    detail.textContent = [
        item.kind && item.kind !== "login" ? profile.title : "",
        item.username,
        State.hostOf(item.site) === "this site" ? "" : State.hostOf(item.site),
    ]
        .filter(Boolean)
        .join(" · ");
    detail.title = detail.textContent;
    who.append(name, detail);
    const buttons = document.createElement("div");
    buttons.className = "buttons";
    const copyResult = field => async button => {
        // Every value goes through the desktop app, which clears the clipboard later.
        const response = await sendMessage({ action: "popupCopyItem", id: item.id, field });
        if (response?.success) {
            say(response.data || "Copied.");
            flash(button);
        } else say(response?.error || "Could not copy.", true);
    };
    const owner = lowerFirst(profile.owner === "Username or email" ? "Username" : profile.owner);
    const secret = lowerFirst(profile.secret);
    if (item.username)
        buttons.append(actionButton(`Copy ${owner}`, `Copy ${owner} for ${item.name}`, copyResult("username")));
    buttons.append(actionButton(`Copy ${secret}`, `Copy ${secret} for ${item.name}`, copyResult("password")));
    if (item.hasTotp)
        buttons.append(actionButton("Copy code", `Copy one-time code for ${item.name}`, copyResult("totp")));
    buttons.append(actionButton("Open", `Open ${item.name} in the desktop app`, () => openInDesktop(item)));
    row.append(who, buttons);
    return row;
}

/** Viewing, editing, and deleting happen in the desktop app, opened at this item. */
async function openInDesktop(item) {
    say(`Opening ${item.name} in the desktop app…`);
    const response = await sendMessage({ action: "openDesktop", id: item.id });
    if (response?.success) say(response.data || `Opening ${item.name} in the desktop app.`);
    else say(response?.error || "Could not open the desktop app.", true);
}

let pendingVaultSearch = null;
async function searchVault() {
    const query = element("vaultQuery").value.trim();
    const request = ++searchRequest;
    const results = element("vaultResults");
    const empty = element("vaultEmpty");
    if (query.length < 2) {
        results.replaceChildren();
        empty.textContent = query ? "Type at least 2 characters to search." : "";
        empty.hidden = !query;
        return;
    }
    const response = await sendMessage({ action: "popupSearch", query });
    if (request !== searchRequest) return;
    results.setAttribute("aria-busy", "false");
    if (!response?.success) {
        results.replaceChildren();
        empty.textContent = response?.error || "Search failed.";
        empty.hidden = false;
        return;
    }
    results.replaceChildren(...response.items.map(resultRow));
    empty.textContent = response.items.length
        ? response.total > response.items.length
            ? `Showing ${response.items.length} of ${response.total}. Type more to narrow the results, or open one in the desktop app to browse.`
            : `${response.items.length} ${response.items.length === 1 ? "item" : "items"} found.`
        : `No items match “${query}”.`;
    empty.hidden = !empty.textContent;
}
element("vaultQuery")?.addEventListener("input", () => {
    clearTimeout(pendingVaultSearch);
    // Old results are no longer actionable once the query changes.
    searchRequest++;
    const results = element("vaultResults");
    results.replaceChildren();
    const query = element("vaultQuery").value.trim();
    const empty = element("vaultEmpty");
    empty.textContent = query.length >= 2 ? "Searching…" : "";
    empty.hidden = !empty.textContent;
    results.setAttribute("aria-busy", String(query.length >= 2));
    pendingVaultSearch = setTimeout(searchVault, 200);
});

// --- Generator ------------------------------------------------------------------
// Settings persist in pmGenerator, shared with the in-page ✨ button.
let generatorStored = {};
function currentGenerator() {
    // Invalid stored settings (from an older version or manual edits) fall back to defaults.
    try {
        return PasswordManagerGenerator.validate(generatorStored);
    } catch (_) {
        return PasswordManagerGenerator.defaults;
    }
}
function generatorView() {
    const settings = currentGenerator();
    const passphrase = settings.mode === "passphrase";
    element("genLength").value = String(passphrase ? settings.words : settings.length);
    element("genLength").min = passphrase ? "3" : "8";
    // The same ranges as the desktop app, CLI and Android: 8–255 characters, 3–64 words.
    element("genLength").max = passphrase ? "64" : "255";
    element("genLength").setAttribute("aria-label", passphrase ? "Number of words" : "Password length");
    element("genLengthValue").textContent = passphrase ? `${settings.words} words` : `${settings.length}`;
    element("genSymbols").checked = settings.symbols;
    element("genSymbols").disabled = passphrase;
    element("genPassphrase").checked = passphrase;
    const extra = { genUppercase: "uppercase", genDigits: "digits", genAmbiguous: "excludeAmbiguous" };
    for (const [id, key] of Object.entries(extra)) {
        const box = element(id);
        if (!box) continue;
        box.checked = settings[key];
        box.disabled = passphrase;
    }
    const separator = element("genSeparator");
    if (separator) {
        separator.value = settings.separator;
        separator.disabled = !passphrase;
    }
    element("genValue").textContent = PasswordManagerGenerator.generate(settings);
}
function saveGenerator(changes) {
    const next = State.generatorSettings(generatorStored, changes);
    try {
        PasswordManagerGenerator.validate(next);
    } catch (error) {
        say(error.message, true);
        generatorView();
        return;
    }
    generatorStored = next;
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
element("genUppercase")?.addEventListener("change", event => saveGenerator({ uppercase: event.target.checked }));
element("genDigits")?.addEventListener("change", event => saveGenerator({ digits: event.target.checked }));
element("genAmbiguous")?.addEventListener("change", event =>
    saveGenerator({ excludeAmbiguous: event.target.checked })
);
element("genSeparator")?.addEventListener("change", event => saveGenerator({ separator: event.target.value }));
element("genCopy").addEventListener("click", async () => {
    const value = element("genValue").textContent;
    if (!value) return;
    // The desktop service copies and clears the clipboard after the configured time.
    if (!State.canCopyLocally(lastStatus || {})) {
        const response = await sendMessage({ action: "popupCopyGenerated", value });
        if (response?.success) say(response.data || "Password copied. The clipboard clears automatically.");
        // A refusal (for example, copying turned off) is respected, not bypassed.
        else say(response?.error || "Could not copy the password.", true);
        return;
    }
    // Without the desktop service nothing can clear the clipboard: ask first.
    if (Date.now() > localCopyArmed) {
        localCopyArmed = Date.now() + 10_000;
        say(
            "The desktop app isn't connected, so the clipboard can't be cleared automatically. Select Copy password again to copy anyway.",
            true
        );
        return;
    }
    localCopyArmed = 0;
    try {
        await navigator.clipboard.writeText(value);
        say("Password copied. Clear your clipboard after pasting.");
    } catch (_) {
        say("Could not copy. Select the password and copy it manually.", true);
    }
});

// --- Setup ----------------------------------------------------------------------

async function copyText(text, done) {
    try {
        await navigator.clipboard.writeText(text);
        say(done);
    } catch (_) {
        say("Could not copy. Select the text and copy it manually.", true);
    }
}
function initSetup() {
    const command = element("setupCommand");
    if (!command) return;
    command.textContent = State.setupCommand(navigator.userAgent || "");
    element("extensionId").textContent = chrome.runtime.id || "";
    element("copySetupCommand").addEventListener("click", () =>
        copyText(command.textContent, "Command copied. Run it in a terminal.")
    );
    element("copyExtensionId").addEventListener("click", () =>
        copyText(element("extensionId").textContent, "Extension ID copied.")
    );
    element("retryBtn").addEventListener("click", async () => {
        say("Checking the connection…");
        await refreshStatus();
        say(lastStatus?.native ? "Connected." : "Still not connected. Reload the extension after setup.", !lastStatus?.native);
    });
}

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
    initSetup();
    chrome.commands?.getAll?.(commands => {
        const footer = element("shortcuts");
        if (footer) footer.textContent = State.shortcutText(commands || []);
    });
    chrome.storage.local.get(["pmStatus", "pmGenerator", "pmNeverSave"], result => {
        generatorStored = result.pmGenerator && typeof result.pmGenerator === "object" ? result.pmGenerator : {};
        generatorView();
        renderNeverSave(State.neverSaveSites(result.pmNeverSave));
        if (result.pmStatus) renderStatus(result.pmStatus);
        refreshStatus();
    });
});

element("lockBtn").addEventListener("click", async () => {
    const response = await sendMessage({ action: "lockVault" });
    if (response?.success) say(response.data);
    else say(response?.error || "Could not reach the desktop app", true);
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
    say(result?.success ? `Operation: ${result.data.state}` : result?.error || "Outcome unavailable", !result?.success);
    if (operationId !== element("operation").value) return;
    reviewedOperationId = result?.success && result.data.state === "unknown" ? operationId : null;
    element("unknownReview").hidden = reviewedOperationId === null;
    await refreshStatus();
});
element("acknowledgeOperation").addEventListener("click", async () => {
    if (!element("inspected").checked || reviewedOperationId !== element("operation").value) return;
    const operationId = element("operation").value;
    const result = await sendMessage({ action: "acknowledgeUnknownOperation", operationId, inspected: true });
    say(result?.success ? "Reviewed outcome acknowledged" : result?.error || "Acknowledgement failed", !result?.success);
    resetReview();
    await refreshStatus();
});

element("openDesktopBtn").addEventListener("click", async () => {
    const button = element("openDesktopBtn");
    button.disabled = true;
    say("Opening desktop app…");
    const response = await sendMessage({ action: "openDesktop" });
    if (response?.success) say("Desktop app launch requested.");
    else say(response?.error || "Could not open the desktop app", true);
    button.disabled = false;
});
