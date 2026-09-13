// ===============================
// Sanitize user-controlled strings before inserting into HTML
// ===============================
function escapeHtml(str) {
    const div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

// ===============================
// Track dropdowns so they can be repositioned
// as the page loads / layout changes
// ===============================
const dropdownRegistry = [];
let layoutObserverStarted = false;

function startLayoutObserver() {
    if (layoutObserverStarted) return;
    layoutObserverStarted = true;

    const reposition = () => requestAnimationFrame(() => {
        for (const dd of dropdownRegistry) dd.position();
    });

    window.addEventListener("load", reposition);
    window.addEventListener("scroll", reposition, true);
    window.addEventListener("resize", reposition);

    // Reposition when the page layout shifts (async content, lazy images, fonts)
    new MutationObserver(reposition).observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["class", "style", "hidden", "type"]
    });
}

// Check whether an element is actually rendered on screen
// (handles fields that are removed, or hidden via display/visibility/opacity)
function isElementVisible(el) {
    if (!el || !el.isConnected) return false;
    let node = el;
    while (node && node.nodeType === 1) {
        const style = getComputedStyle(node);
        if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") {
            return false;
        }
        node = node.parentElement;
    }
    return true;
}

function isUsableInput(input) {
    return input instanceof HTMLInputElement
        && !input.disabled
        && !input.readOnly
        && isElementVisible(input);
}

function scopeInputs(scope) {
    if (scope instanceof HTMLFormElement) {
        return Array.from(scope.elements).filter(element => element instanceof HTMLInputElement);
    }
    return Array.from(scope.querySelectorAll("input"));
}

// Prefer the browser's explicit form association (including form="id" fields).
// For sites built without <form>, use the smallest nearby container that holds
// a plausible credential pair instead of searching the entire page.
function credentialScope(input) {
    if (input.form) return input.form;

    const explicitScope = input.closest("[role='form'], dialog");
    if (explicitScope) return explicitScope;

    let candidate = input.parentElement;
    while (candidate && candidate !== document.body) {
        const fields = Array.from(candidate.querySelectorAll("input")).filter(isUsableInput);
        const hasPassword = fields.some(field => field.type === "password");
        const possibleUserFields = fields.filter(field =>
            USERNAME_INPUT_TYPES.has(field.type) && !hasSearchHint(field)
        );
        if (hasPassword && possibleUserFields.length > 0) return candidate;
        candidate = candidate.parentElement;
    }

    return input.parentElement || document;
}

function autocompleteTokens(input) {
    return (input.autocomplete || "").toLowerCase().split(/\s+/).filter(Boolean);
}

function isNewPasswordInput(input) {
    if (autocompleteTokens(input).includes("new-password")) return true;
    return inputDescriptors(input).some(value => /confirm|repeat|retype|new[-_ ]?pass|create[-_ ]?pass/i.test(value));
}

function isLoginPasswordInput(input) {
    return isUsableInput(input) && input.type === "password" && !isNewPasswordInput(input);
}

function usernameCandidates(fields) {
    return fields.filter(field =>
        isUsableInput(field)
        && USERNAME_INPUT_TYPES.has(field.type)
        && !hasSearchHint(field)
    );
}

function chooseUsernameField(fields, anchor) {
    const candidates = usernameCandidates(fields);
    const beforeAnchor = anchor
        ? candidates.filter(field => fields.indexOf(field) < fields.indexOf(anchor))
        : candidates;
    const pool = beforeAnchor.length > 0 ? beforeAnchor : candidates;
    return pool.find(field => autocompleteTokens(field).some(token => token === "username" || token === "email"))
        || pool.find(hasUsernameHint)
        || pool.at(-1)
        || null;
}

function choosePasswordField(fields, anchor) {
    const candidates = fields.filter(isLoginPasswordInput);
    return candidates.find(field => autocompleteTokens(field).includes("current-password"))
        || (anchor && candidates.find(field => fields.indexOf(field) > fields.indexOf(anchor)))
        || candidates[0]
        || null;
}

function credentialFields(input) {
    const scope = credentialScope(input);
    const fields = scopeInputs(scope);
    return {
        scope,
        usernameField: USERNAME_INPUT_TYPES.has(input.type)
            ? input
            : chooseUsernameField(fields, input),
        passwordField: isLoginPasswordInput(input)
            ? input
            : choosePasswordField(fields, input)
    };
}

// Frameworks such as React observe the native value setter and input/change
// events. Using both keeps their internal form state synchronized with autofill.
function fillInput(input, value) {
    if (!input || !isUsableInput(input)) return;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    if (setter) setter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
}

// Fetch the current saved accounts for a domain from the background
function fetchAccounts(domain) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage(
            { action: "getCredentials", domain: domain },
            (response) => {
                let accounts = [];
                if (response && response.success) {
                    try {
                        accounts = JSON.parse(response.data);
                        if (!Array.isArray(accounts)) accounts = [];
                    } catch (e) {
                        accounts = [];
                    }
                }
                resolve(accounts);
            }
        );
    });
}

function fetchTotp(id) {
    return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({ action: "getTotp", id }, (response) => {
            if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
            } else if (!response?.success) {
                reject(new Error(response?.error || "TOTP unavailable"));
            } else {
                resolve(response.data);
            }
        });
    });
}

function accountUsername(account) {
    return account.username && account.username !== "None" ? account.username : "";
}

function createDropdownButton(input, accounts) {
    if (input.dataset.hasCredentialDropdown) return;
    input.dataset.hasCredentialDropdown = "true";

    // Create button
    const button = document.createElement("button");
    button.type = "button";
    button.innerText = "🔑";
    Object.assign(button.style, {
        position: "fixed",
        border: "none",
        background: "transparent",
        cursor: "pointer",
        fontSize: "16px",
        zIndex: "2147483647",
        padding: "0",
        margin: "0",
        display: "none"
    });

    document.body.appendChild(button);

    // Create dropdown
    const menu = document.createElement("div");
    Object.assign(menu.style, {
        position: "fixed",
        background: "#fff",
        color: "#000",
        border: "1px solid #ccc",
        display: "none",
        zIndex: "2147483647",
        minWidth: "180px",
        boxShadow: "0 4px 12px rgba(0,0,0,0.25)",
        fontFamily: "Arial, sans-serif",
        fontSize: "14px",
        textAlign: "left"
    });

    document.body.appendChild(menu);

    // Position button over the input
    function positionButton() {
        if (!isElementVisible(input)) {
            button.style.display = "none";
            menu.style.display = "none";
            return;
        }
        const rect = input.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) {
            button.style.display = "none";
            menu.style.display = "none";
            return;
        }
        button.style.display = "";
        button.style.left = rect.right - 24 + "px";
        button.style.top = rect.top + rect.height / 2 - 14 + "px";
    }

    function positionMenu() {
        menu.style.display = "block";
        menu.style.visibility = "hidden";
        const rect = button.getBoundingClientRect();
        const menuWidth = menu.offsetWidth;
        const menuHeight = menu.offsetHeight;

        let left = rect.left;
        if (left + menuWidth > window.innerWidth - 4) {
            left = Math.max(4, window.innerWidth - menuWidth - 4);
        }
        let top = rect.bottom;
        if (top + menuHeight > window.innerHeight - 4) {
            top = rect.top - menuHeight;
        }
        if (top < 4) top = 4;

        menu.style.left = left + "px";
        menu.style.top = top + "px";
        menu.style.visibility = "";
    }

    positionButton();

    // Keep the key glued to the field as the page finishes loading / layout shifts
    dropdownRegistry.push({ position: positionButton });
    startLayoutObserver();

    function buildMenuItems(accountList) {
        menu.innerHTML = "";

        if (!accountList || accountList.length === 0) {
            const empty = document.createElement("div");
            empty.innerText = "No saved accounts for this site";
            Object.assign(empty.style, {
                padding: "8px 12px",
                color: "#666",
                fontStyle: "italic"
            });
            menu.appendChild(empty);
            return;
        }

        accountList.forEach(acc => {
            const item = document.createElement("div");
            item.innerText = accountUsername(acc) || "(no username)";
            Object.assign(item.style, {
                padding: "8px 12px",
                cursor: "pointer",
                color: "#000",
                background: "#fff"
            });

            item.addEventListener("mouseenter", () => {
                item.style.background = "#eee";
            });

            item.addEventListener("mouseleave", () => {
                item.style.background = "#fff";
            });

            item.addEventListener("click", (e) => {
                e.preventDefault();

                const fields = credentialFields(input);
                fillInput(fields.usernameField, accountUsername(acc));
                fillInput(fields.passwordField, acc.password);
                (fields.passwordField || fields.usernameField)?.focus();

                menu.style.display = "none";
            });

            menu.appendChild(item);
        });
    }

    buildMenuItems(accounts);

    button.addEventListener("click", async (e) => {
        e.preventDefault();
        e.stopPropagation();

        positionButton();

        if (menu.style.display === "block") {
            menu.style.display = "none";
            return;
        }

        // Refresh from the vault so every saved username for this site appears
        const fresh = await fetchAccounts(window.location.hostname);
        buildMenuItems(fresh);
        positionMenu();
    });

    document.addEventListener("click", (e) => {
        if (!menu.contains(e.target) && e.target !== button) {
            menu.style.display = "none";
        }
    });
}

function createTotpButton(input, accounts) {
    if (input.dataset.hasTotpDropdown) return;
    input.dataset.hasTotpDropdown = "true";

    const button = document.createElement("button");
    button.type = "button";
    button.innerText = "🔐";
    button.setAttribute("aria-label", "Fill authenticator code");
    button.title = "Fill authenticator code";
    Object.assign(button.style, {
        position: "fixed",
        border: "none",
        background: "transparent",
        cursor: "pointer",
        fontSize: "16px",
        zIndex: "2147483647",
        padding: "0",
        margin: "0",
        display: "none"
    });
    document.body.appendChild(button);

    const menu = document.createElement("div");
    Object.assign(menu.style, {
        position: "fixed",
        background: "#fff",
        color: "#000",
        border: "1px solid #ccc",
        display: "none",
        zIndex: "2147483647",
        minWidth: "210px",
        boxShadow: "0 4px 12px rgba(0,0,0,0.25)",
        fontFamily: "Arial, sans-serif",
        fontSize: "14px",
        textAlign: "left"
    });
    document.body.appendChild(menu);

    function positionButton() {
        if (!isElementVisible(input)) {
            button.style.display = "none";
            menu.style.display = "none";
            return;
        }
        const rect = input.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) {
            button.style.display = "none";
            menu.style.display = "none";
            return;
        }
        button.style.display = "";
        button.style.left = rect.right - 24 + "px";
        button.style.top = rect.top + rect.height / 2 - 14 + "px";
    }

    function positionMenu() {
        menu.style.display = "block";
        menu.style.visibility = "hidden";
        const rect = button.getBoundingClientRect();
        const menuWidth = menu.offsetWidth;
        const menuHeight = menu.offsetHeight;
        const left = Math.min(rect.left, Math.max(4, window.innerWidth - menuWidth - 4));
        let top = rect.bottom;
        if (top + menuHeight > window.innerHeight - 4) top = rect.top - menuHeight;
        menu.style.left = Math.max(4, left) + "px";
        menu.style.top = Math.max(4, top) + "px";
        menu.style.visibility = "";
    }

    function buildMenuItems(accountList) {
        menu.innerHTML = "";
        const totpAccounts = (accountList || []).filter(account => account.has_totp);
        if (totpAccounts.length === 0) {
            const empty = document.createElement("div");
            empty.innerText = "No authenticator configured for this site";
            Object.assign(empty.style, { padding: "8px 12px", color: "#666", fontStyle: "italic" });
            menu.appendChild(empty);
            return;
        }

        totpAccounts.forEach(account => {
            const item = document.createElement("button");
            item.type = "button";
            item.innerText = accountUsername(account) || account.name || "(no username)";
            Object.assign(item.style, {
                display: "block",
                width: "100%",
                padding: "8px 12px",
                border: "none",
                cursor: "pointer",
                color: "#000",
                background: "#fff",
                textAlign: "left"
            });
            item.addEventListener("mouseenter", () => { item.style.background = "#eee"; });
            item.addEventListener("mouseleave", () => { item.style.background = "#fff"; });
            item.addEventListener("click", async (event) => {
                event.preventDefault();
                event.stopPropagation();
                item.disabled = true;
                item.innerText = "Generating code…";
                try {
                    const totp = await fetchTotp(account.id);
                    fillInput(input, totp.code);
                    input.focus();
                    button.title = `Authenticator code filled (${totp.expires_in}s remaining)`;
                    menu.style.display = "none";
                } catch (error) {
                    item.innerText = "Could not get code — try again";
                    item.title = error.message;
                    item.disabled = false;
                }
            });
            menu.appendChild(item);
        });
    }

    buildMenuItems(accounts);
    positionButton();
    dropdownRegistry.push({ position: positionButton });
    startLayoutObserver();

    button.addEventListener("click", async (event) => {
        event.preventDefault();
        event.stopPropagation();
        positionButton();
        if (menu.style.display === "block") {
            menu.style.display = "none";
            return;
        }
        const fresh = await fetchAccounts(window.location.hostname);
        buildMenuItems(fresh);
        positionMenu();
    });

    document.addEventListener("click", event => {
        if (!menu.contains(event.target) && event.target !== button) menu.style.display = "none";
    });
}

// Generate locally with the browser CSPRNG. Every generated password contains
// upper/lowercase letters, a digit, and a symbol; no secret crosses an extension
// or native-messaging boundary until the user chooses to save the form.
function secureRandomIndex(limit) {
    const ceiling = Math.floor(0x100000000 / limit) * limit;
    const value = new Uint32Array(1);
    do {
        crypto.getRandomValues(value);
    } while (value[0] >= ceiling);
    return value[0] % limit;
}

function generatePagePassword(length = 20) {
    const groups = [
        "ABCDEFGHJKLMNPQRSTUVWXYZ",
        "abcdefghijkmnopqrstuvwxyz",
        "23456789",
        "!@#$%^&*-_=+"
    ];
    const all = groups.join("");
    const characters = groups.map(group => group[secureRandomIndex(group.length)]);
    while (characters.length < length) {
        characters.push(all[secureRandomIndex(all.length)]);
    }
    for (let index = characters.length - 1; index > 0; index--) {
        const swap = secureRandomIndex(index + 1);
        [characters[index], characters[swap]] = [characters[swap], characters[index]];
    }
    return characters.join("");
}

function createGeneratorButton(input) {
    if (input.dataset.hasPasswordGenerator) return;
    input.dataset.hasPasswordGenerator = "true";

    const button = document.createElement("button");
    button.type = "button";
    button.innerText = "✨";
    button.title = "Generate a strong password";
    button.setAttribute("aria-label", "Generate a strong password");
    Object.assign(button.style, {
        position: "fixed",
        border: "none",
        background: "transparent",
        cursor: "pointer",
        fontSize: "15px",
        zIndex: "2147483647",
        padding: "0",
        margin: "0",
        display: "none"
    });
    document.body.appendChild(button);

    function positionButton() {
        if (!isElementVisible(input)) {
            button.style.display = "none";
            return;
        }
        const rect = input.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) {
            button.style.display = "none";
            return;
        }
        button.style.display = "";
        button.style.left = rect.right - 24 + "px";
        button.style.top = rect.top + rect.height / 2 - 14 + "px";
    }

    button.addEventListener("click", event => {
        event.preventDefault();
        event.stopPropagation();
        const password = generatePagePassword();
        const fields = scopeInputs(credentialScope(input)).filter(isNewPasswordInput);
        const targets = fields.length > 0 ? fields : [input];
        targets.forEach(field => fillInput(field, password));
        lastCredentialInput = input;
        input.focus();
        button.title = "Strong password generated and filled";
    });

    positionButton();
    dropdownRegistry.push({ position: positionButton });
    startLayoutObserver();
}

// ===============================
// Only treat inputs as credential fields when
// they look like a username or password
// ===============================
const USERNAME_HINT_RE = /user(name)?|login|e-?mail|account|sign-?in|auth/i;
const SEARCH_HINT_RE = /search|query|lookup|find/i;
const TOTP_HINT_RE = /\b(otp|totp|2fa|mfa)\b|one[-_ ]?time|verification[-_ ]?(code|token)|security[-_ ]?code|authenticator[-_ ]?code/i;
const USERNAME_INPUT_TYPES = new Set(["text", "email", "tel"]);

function inputDescriptors(input) {
    return [
        input.name,
        input.id,
        input.className,
        input.autocomplete,
        input.getAttribute("type"),
        input.getAttribute("placeholder"),
        input.getAttribute("aria-label"),
        input.getAttribute("role")
    ].filter(Boolean).map(String);
}

function hasUsernameHint(input) {
    return inputDescriptors(input).some(value => USERNAME_HINT_RE.test(value));
}

function hasSearchHint(input) {
    return input.type === "search"
        || input.getAttribute("role") === "searchbox"
        || inputDescriptors(input).some(value => SEARCH_HINT_RE.test(value));
}

function isTotpInput(input) {
    if (!isUsableInput(input)) return false;
    if (autocompleteTokens(input).includes("one-time-code")) return true;
    if (!["text", "tel", "number"].includes(input.type)) return false;
    return inputDescriptors(input).some(value => TOTP_HINT_RE.test(value));
}

// Some login pages use an unlabelled text box for the username. In that case,
// only accept the closest eligible field before a password in the same form.
// This avoids treating unrelated page-level text/search fields as credentials.
function isUsernameBeforePassword(input) {
    const form = input.form;
    if (!form) return false;

    const fields = scopeInputs(form);
    const passwordIndex = fields.findIndex(isLoginPasswordInput);
    if (passwordIndex < 0) return false;

    const candidates = fields
        .slice(0, passwordIndex)
        .filter(field => isUsableInput(field) && USERNAME_INPUT_TYPES.has(field.type) && !hasSearchHint(field));
    return candidates.at(-1) === input;
}

function isCredentialInput(input) {
    if (!isUsableInput(input)) return false;
    const type = input.type;
    if (type === "password") return !isNewPasswordInput(input);

    if (!USERNAME_INPUT_TYPES.has(type) || hasSearchHint(input)) {
        return false;
    }

    // Explicit hints support multi-step login pages where the password field
    // is not present yet; the same-form fallback supports minimal login forms.
    return hasUsernameHint(input) || isUsernameBeforePassword(input);
}

// ===============================
// Attach to username/password inputs
// ===============================
function attachToInputs(accounts) {
    document.querySelectorAll("input").forEach(input => {
        // Ignore extension UI elements
        if (input.classList.contains("my-extension-ui")) return;
        if (isCredentialInput(input)) {
            createDropdownButton(input, accounts);
        }
        if (isUsableInput(input) && input.type === "password" && isNewPasswordInput(input)) {
            createGeneratorButton(input);
        }
        if (isTotpInput(input)) {
            createTotpButton(input, accounts);
        }
    });
}

// ===============================
// Observe DOM safely (no loop)
// ===============================
function observeInputs(accounts) {
    const observer = new MutationObserver((mutations) => {
        let foundNewInput = false;

        for (const mutation of mutations) {
            if (mutation.type === "attributes" && mutation.target instanceof HTMLInputElement) {
                foundNewInput = true;
            }
            for (const node of mutation.addedNodes) {
                if (node.nodeType === 1 &&
                    (node.matches?.("input") || node.querySelector?.("input"))) {
                    foundNewInput = true;
                }
            }
        }

        if (foundNewInput) {
            attachToInputs(accounts);
        }
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["class", "style", "hidden", "type", "autocomplete", "disabled", "readonly"]
    });

    // Initial run
    attachToInputs(accounts);
}
// ===============================
// Get domain from URL
// ===============================
function getDomainFromUrl(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname;
    } catch {
        return url;
    }
}

// ===============================
// Find login form credentials
// ===============================
let storedUsername = "";
let storedDomain = "";
let lastCredentialInput = null;

function credentialsFromScope(scope) {
    const fields = scopeInputs(scope);
    const filledPasswords = fields.filter(field =>
        isUsableInput(field) && field.type === "password" && field.value
    );
    const newPasswords = filledPasswords.filter(isNewPasswordInput);
    const currentPasswords = filledPasswords.filter(field => !isNewPasswordInput(field));
    // Capture a newly chosen password on registration/change-password forms,
    // but never autofill these fields (credentialFields excludes them).
    const passwordField = newPasswords.find(field => autocompleteTokens(field).includes("new-password"))
        || newPasswords.find(field => !inputDescriptors(field).some(value => /confirm|repeat|retype/i.test(value)))
        || newPasswords[0]
        || currentPasswords.find(field => autocompleteTokens(field).includes("current-password"))
        || currentPasswords[0]
        || null;
    if (!passwordField) return { username: "", password: "", scope };

    const candidates = usernameCandidates(fields);
    const preceding = candidates.filter(field => fields.indexOf(field) < fields.indexOf(passwordField));
    const pool = preceding.length > 0 ? preceding : candidates;
    const valued = pool.filter(field => field.value.trim());
    const usernameField = valued.find(field => autocompleteTokens(field).some(token => token === "username" || token === "email"))
        || valued.find(hasUsernameHint)
        || valued.at(-1)
        || null;

    return {
        username: usernameField ? usernameField.value.trim() : "",
        password: passwordField.value,
        scope
    };
}

function findLoginCredentials(source = null) {
    if (source instanceof HTMLFormElement) {
        return credentialsFromScope(source);
    }
    if (source instanceof HTMLInputElement) {
        return credentialsFromScope(credentialScope(source));
    }

    if (lastCredentialInput && lastCredentialInput.isConnected) {
        const recent = credentialsFromScope(credentialScope(lastCredentialInput));
        if (recent.password) return recent;
    }

    const seen = new Set();
    for (const passwordField of document.querySelectorAll("input[type='password']")) {
        if (!isUsableInput(passwordField) || !passwordField.value) continue;
        const scope = credentialScope(passwordField);
        if (seen.has(scope)) continue;
        seen.add(scope);
        const credentials = credentialsFromScope(scope);
        if (credentials.password) return credentials;
    }

    return { username: "", password: "", scope: null };
}

function storeUsernameForLater(username) {
    if (username) {
        storedUsername = username;
        storedDomain = getDomainFromUrl(window.location.href);
    } else {
        storedUsername = "";
        storedDomain = "";
    }
}

// ===============================
// Check if credentials match saved ones
// ===============================
function findMatchingAccount(username, password, accounts) {
    return accounts.find(acc => {
        if (username) {
            return accountUsername(acc) === username && acc.password === password;
        }
        return acc.password === password;
    });
}

function findAccountByUsername(username, accounts) {
    return accounts.find(acc => accountUsername(acc) === username);
}

// On password-only logins the username field may be missing; fall back to
// the last username seen on this domain, or the site's only saved account.
function resolveUsername(username, accounts) {
    if (username) return username;
    if (storedUsername && storedDomain === getDomainFromUrl(window.location.href)) {
        return storedUsername;
    }
    if (accounts.length === 1 && accountUsername(accounts[0])) {
        return accountUsername(accounts[0]);
    }
    return "";
}

// ===============================
// Show custom prompt modal
// ===============================
let modalOpen = false;

function showPromptModal(title, message, showUpdateOption = false, oldUsername = "", oldPassword = "", showNameInput = false, existingName = "", showUsernameInput = false, usernameValue = "") {
    modalOpen = true;
    const originalSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function() {
        if (modalOpen) return;
        return originalSubmit.call(this);
    };
    return new Promise((resolve) => {
        const overlay = document.createElement("div");
        Object.assign(overlay.style, {
            position: "fixed",
            top: "0",
            left: "0",
            width: "100%",
            height: "100%",
            background: "rgba(0,0,0,0.5)",
            zIndex: "2147483647",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            pointerEvents: "all"
        });

        overlay.addEventListener("click", (e) => e.stopPropagation());
        overlay.addEventListener("submit", (e) => e.preventDefault());
        overlay.addEventListener("keydown", (e) => e.preventDefault());

        const modal = document.createElement("div");
        Object.assign(modal.style, {
            background: "#fff",
            padding: "20px",
            borderRadius: "8px",
            maxWidth: "320px",
            width: "90%",
            boxShadow: "0 4px 12px rgba(0,0,0,0.25)",
            pointerEvents: "all"
        });
        modal.addEventListener("click", (e) => e.stopPropagation());
        modal.addEventListener("keydown", (e) => e.stopPropagation());

        const nameInputHTML = showNameInput ? `
            <input id="pmNameInput" type="text" placeholder="Name (e.g., Work, Personal)" value="${escapeHtml(existingName)}" style="padding: 8px; margin-bottom: 15px; width: 100%; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px;" />
        ` : "";

        const usernameInputHTML = showUsernameInput ? `
            <input id="pmUsernameInput" type="text" placeholder="Username" value="${escapeHtml(usernameValue)}" style="padding: 8px; margin-bottom: 15px; width: 100%; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px;" />
        ` : "";

        modal.innerHTML = `
            <h3 style="margin: 0 0 10px 0;">${title}</h3>
            <p style="margin: 0 0 15px 0; color: #666;">${message}</p>
            ${usernameInputHTML}
            ${nameInputHTML}
            <div style="display: flex; flex-direction: column; gap: 8px;">
                <button type="button" id="pmAddBtn" style="padding: 10px; background: #4285f4; color: white; border: none; border-radius: 4px; cursor: pointer;">Add as New Account</button>
                ${showUpdateOption ? `<button type="button" id="pmUpdateBtn" style="padding: 10px; background: #34a853; color: white; border: none; border-radius: 4px; cursor: pointer;">Update Existing</button>` : ""}
                <button type="button" id="pmCancelBtn" style="padding: 10px; background: #ccc; color: #333; border: none; border-radius: 4px; cursor: pointer;">Ignore</button>
            </div>
        `;

        overlay.appendChild(modal);
        document.body.appendChild(overlay);

        const cleanup = () => {
            modalOpen = false;
            HTMLFormElement.prototype.submit = originalSubmit;
        };

        document.getElementById("pmAddBtn").addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();
            const name = showNameInput ? document.getElementById("pmNameInput").value.trim() : "";
            const username = showUsernameInput ? document.getElementById("pmUsernameInput").value.trim() : "";
            document.body.removeChild(overlay);
            cleanup();
            resolve({ action: "add", name, username });
        });

        const updateBtn = document.getElementById("pmUpdateBtn");
        if (updateBtn) {
            updateBtn.addEventListener("click", (e) => {
                e.preventDefault();
                e.stopPropagation();
                e.stopImmediatePropagation();
                const name = showNameInput ? document.getElementById("pmNameInput").value.trim() : existingName;
                const username = showUsernameInput ? document.getElementById("pmUsernameInput").value.trim() : "";
                document.body.removeChild(overlay);
                cleanup();
                resolve({ action: "update", name, username });
            });
        }

        document.getElementById("pmCancelBtn").addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();
            document.body.removeChild(overlay);
            cleanup();
            resolve({ action: "cancel" });
        });
    });
}

// ===============================
// Ask the user whether to save/update when credentials
// don't match an existing entry exactly
// ===============================
async function promptForCredentials(username, password, accounts, domain = currentDomain) {
    const existing = findAccountByUsername(username, accounts);
    const hasAccounts = accounts.length > 0;
    const updateTarget = existing || (hasAccounts ? accounts[0] : null);

    setPopupPending({
        username,
        password,
        accountName: updateTarget ? updateTarget.name : "",
        hasAccounts
    }, domain);

    const message = existing
        ? `An account with this username already exists, but the password is different. What would you like to do?`
        : hasAccounts
            ? "These credentials don't match any saved account. What would you like to do?"
            : "Would you like to save these credentials?";

    const result = await showPromptModal(
        "Save Credentials",
        message,
        hasAccounts,
        existing ? existing.username : "",
        existing ? existing.password : "",
        true,
        updateTarget ? updateTarget.name : "",
        !username,
        existing ? existing.username : ""
    );

    return { result, updateTarget };
}

// ===============================
// When a login happens inside an iframe, relay it to the top
// frame so the prompt is shown in the main window where it's visible.
// ===============================
function relayLoginToParent(username, password, accounts) {
    return new Promise((resolve) => {
        const token = Math.random().toString(36).slice(2);

        const handler = (event) => {
            if (event.source !== window.parent) return;
            if (event.data && event.data.type === "PM_LOGIN_RESULT" && event.data.token === token) {
                window.removeEventListener("message", handler);
                resolve(event.data);
            }
        };

        window.addEventListener("message", handler);
        chrome.runtime.sendMessage({
            action: "relayToParent",
            data: {
                type: "PM_LOGIN",
                token,
                domain: currentDomain,
                username,
                password,
                accountName: accounts.length > 0 ? accounts[0].name : "",
                hasAccounts: accounts.length > 0
            }
        });

        // If the parent never answers, don't block the login
        setTimeout(() => resolve({ action: "ignore" }), 30000);
    });
}

// ===============================
// Track popup state across pages
// ===============================
let popupResolved = false;
let currentDomain = window.location.hostname;

function getBaseDomain(hostname) {
    const parts = hostname.split(".");
    if (parts.length <= 2) return hostname;
    const twoLetterTld = /^[a-z]{2}$/.test(parts[parts.length - 1]);
    return parts.slice(-(twoLetterTld && parts.length > 3 ? 3 : 2)).join(".");
}

function isSameSite(a, b) {
    if (!a || !b) return false;
    return a === b
        || a.endsWith("." + b)
        || b.endsWith("." + a)
        || getBaseDomain(a) === getBaseDomain(b);
}

const PENDING_TIMEOUT = 10 * 60 * 1000;

function setPopupPending(pendingData, domain = currentDomain) {
    chrome.storage.session.set({
        pmPopupPending: {
            domain: domain,
            username: pendingData.username,
            password: pendingData.password,
            accountName: pendingData.accountName,
            hasAccounts: pendingData.hasAccounts,
            time: Date.now()
        }
    });
}

function clearPopupPending() {
    chrome.storage.session.remove("pmPopupPending");
}

function isPopupPending() {
    return new Promise((resolve) => {
        chrome.storage.session.get("pmPopupPending", (result) => {
            const p = result.pmPopupPending;
            if (p && isSameSite(p.domain, currentDomain) && Date.now() - p.time < PENDING_TIMEOUT) {
                resolve(p);
            } else {
                if (p && Date.now() - p.time >= PENDING_TIMEOUT) {
                    clearPopupPending();
                }
                resolve(null);
            }
        });
    });
}

// ===============================
// Request credentials from background
// ===============================
async function initExtension() {
    // Do not place plaintext vault credentials in every matching page at load.
    // The picker fetches on click, and save/update checks fetch on submission.
    observeInputs([]);

    // Remember the last username typed on this domain so password-only
    // login steps (and the save prompt) know which account is logging in.
    document.addEventListener("input", (e) => {
        const t = e.target;
        if (!(t instanceof HTMLInputElement) || !isCredentialInput(t)) return;
        lastCredentialInput = t;
        if (USERNAME_INPUT_TYPES.has(t.type) && t.value.trim()) {
            storeUsernameForLater(t.value.trim());
        }
    }, true);

    document.addEventListener("focusin", (e) => {
        if (e.target instanceof HTMLInputElement && isCredentialInput(e.target)) {
            lastCredentialInput = e.target;
        }
    }, true);

    const pendingPopup = await isPopupPending();
    if (pendingPopup && !modalOpen) {
        modalOpen = true;
        const pendingDomain = pendingPopup.domain;
        const domainAccounts = await fetchAccounts(pendingDomain);
        if (findMatchingAccount(pendingPopup.username, pendingPopup.password, domainAccounts)) {
            modalOpen = false;
            popupResolved = true;
            clearPopupPending();
            return;
        }
        const { result, updateTarget } = await promptForCredentials(
            pendingPopup.username,
            pendingPopup.password,
            domainAccounts,
            pendingDomain
        );

        modalOpen = false;
        popupResolved = true;
        clearPopupPending();

        const saveUsername = result.username || pendingPopup.username;

        if (result.action === "add") {
            chrome.runtime.sendMessage({
                action: "saveCredentials",
                domain: pendingDomain,
                username: saveUsername,
                password: pendingPopup.password,
                name: result.name
            });
        } else if (result.action === "update" && updateTarget) {
            chrome.runtime.sendMessage({
                action: "updateCredentials",
                domain: pendingDomain,
                username: saveUsername,
                password: pendingPopup.password,
                name: updateTarget.name,
                id: updateTarget.id
            });
        }
        return;
    }

    document.addEventListener("submit", async (e) => {
        if (modalOpen || popupResolved) return;

        const { username: rawUsername, password } = findLoginCredentials(e.target);
        if (!password) return;
        const accounts = await fetchAccounts(currentDomain);
        const username = resolveUsername(rawUsername, accounts);
        if (rawUsername) storeUsernameForLater(rawUsername);

        const match = findMatchingAccount(username, password, accounts);
        if (!match) {
            e.preventDefault();

            // Login happened inside an iframe: show the prompt in the top
            // window (visible there), then let the iframe submit.
            if (window !== window.top) {
                await relayLoginToParent(username, password, accounts);
                e.target.submit();
                return;
            }

            modalOpen = true;
            const domain = currentDomain;

            const { result, updateTarget } = await promptForCredentials(username, password, accounts, domain);

            modalOpen = false;
            popupResolved = true;
            clearPopupPending();

            const saveUsername = result.username || username;

            if (result.action === "add") {
                chrome.runtime.sendMessage({
                    action: "saveCredentials",
                    domain: domain,
                    username: saveUsername,
                    password: password,
                    name: result.name
                });
            } else if (result.action === "update" && updateTarget) {
                chrome.runtime.sendMessage({
                    action: "updateCredentials",
                    domain: domain,
                    username: saveUsername,
                    password: password,
                    name: updateTarget.name,
                    id: updateTarget.id
                });
            }
            e.target.submit();
        }
    }, true);

    // Top frame: handle logins relayed from login forms inside iframes.
    if (window === window.top) {
        window.addEventListener("message", async (event) => {
            if (event.source === window) return;
            const data = event.data;
            if (!data || data.type !== "PM_LOGIN") return;
            let sourceDomain = "";
            try {
                sourceDomain = new URL(event.origin).hostname;
            } catch (_) {
                return;
            }
            if (sourceDomain !== data.domain) return;

            if (modalOpen || popupResolved) {
                event.source.postMessage({ type: "PM_LOGIN_RESULT", action: "ignore", token: data.token }, event.origin);
                return;
            }

            modalOpen = true;
            const domainAccounts = await fetchAccounts(data.domain);
            const { result, updateTarget } = await promptForCredentials(
                data.username,
                data.password,
                domainAccounts,
                data.domain
            );

            modalOpen = false;
            popupResolved = true;
            clearPopupPending();

            const saveUsername = result.username || data.username;

            if (result.action === "add") {
                chrome.runtime.sendMessage({
                    action: "saveCredentials",
                    domain: data.domain,
                    username: saveUsername,
                    password: data.password,
                    name: result.name
                });
            } else if (result.action === "update" && updateTarget) {
                chrome.runtime.sendMessage({
                    action: "updateCredentials",
                    domain: data.domain,
                    username: saveUsername,
                    password: data.password,
                    name: updateTarget.name,
                    id: updateTarget.id
                });
            }

            event.source.postMessage({ type: "PM_LOGIN_RESULT", action: result.action, token: data.token }, event.origin);
        });
    }

    // Catch logins that navigate/redirect without a form submit event
    // (e.g. fetch + window.location, or form.submit() in JS), so the
    // save/update prompt still appears on the landing page.
    window.addEventListener("pagehide", () => {
        if (modalOpen || popupResolved) return;

        const { username: rawUsername, password } = findLoginCredentials();
        if (!password) return;
        const username = resolveUsername(rawUsername, []);
        if (rawUsername) storeUsernameForLater(rawUsername);

        setPopupPending({
            username,
            password,
            accountName: "",
            hasAccounts: false
        });

        // Relay from a subframe so the parent can show the prompt live.
        if (window !== window.top) {
            chrome.runtime.sendMessage({
                action: "relayToParent",
                data: {
                    type: "PM_LOGIN",
                    token: Math.random().toString(36).slice(2),
                    domain: currentDomain,
                    username,
                    password,
                    accountName: "",
                    hasAccounts: false
                }
            });
        }
    });
}

initExtension().catch(error => console.log("Password Manager error:", error));
