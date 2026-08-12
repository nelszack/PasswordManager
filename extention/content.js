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
            item.innerText = acc.username;
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

                if (input.type !== "password") {
                    input.value = acc.username;
                    input.dispatchEvent(new Event("input", { bubbles: true }));
                }

                const passwordField = document.querySelector("input[type='password']");
                if (passwordField) {
                    passwordField.value = acc.password;
                    passwordField.dispatchEvent(new Event("input", { bubbles: true }));
                }

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

// ===============================
// Only treat inputs as credential fields when
// they look like a username or password
// ===============================
const USERNAME_HINT_RE = /user|login|email|account|signin|sign-in|auth/i;

function hasUsernameHint(input) {
    const fields = [
        input.name,
        input.id,
        input.className,
        input.autocomplete,
        input.getAttribute("placeholder"),
        input.getAttribute("aria-label")
    ];
    return fields.some(f => f && USERNAME_HINT_RE.test(String(f)));
}

function isNearPassword(input) {
    const form = input.form;
    if (form && form.querySelector("input[type='password']")) return true;

    let container = input.parentElement;
    for (let i = 0; i < 3 && container; i++) {
        if (container.querySelector("input[type='password']")) return true;
        container = container.parentElement;
    }

    return false;
}

function isCredentialInput(input) {
    const type = input.type;
    if (type === "password") return true;

    if (type !== "text" && type !== "email" && type !== "username" && type !== "tel") {
        return false;
    }

    // Username fields don't always sit next to a password field
    // (multi-step logins), so also accept fields with username-like hints.
    return isNearPassword(input) || hasUsernameHint(input);
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
    });
}

// ===============================
// Observe DOM safely (no loop)
// ===============================
function observeInputs(accounts) {
    const observer = new MutationObserver((mutations) => {
        let foundNewInput = false;

        for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
                if (
                    node.nodeType === 1 &&
                    node.querySelector &&
                    node.querySelector("input")
                ) {
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
        subtree: true
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

function findLoginCredentials() {
    const usernameInputs = document.querySelectorAll(
        "input[type='text'], input[type='email'], input[type='username'], input[type='tel']"
    );
    const passwordInputs = document.querySelectorAll("input[type='password']");

    let username = "";
    let password = "";

    for (const input of usernameInputs) {
        if (input.value.trim()) {
            username = input.value.trim();
            break;
        }
    }

    for (const input of passwordInputs) {
        if (input.value) {
            password = input.value;
            break;
        }
    }

    return { username, password };
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
            return acc.username === username && acc.password === password;
        }
        return acc.password === password;
    });
}

function findAccountByUsername(username, accounts) {
    return accounts.find(acc => acc.username === username);
}

// On password-only logins the username field may be missing; fall back to
// the last username seen on this domain, or the site's only saved account.
function resolveUsername(username, accounts) {
    if (username) return username;
    if (storedUsername && storedDomain === getDomainFromUrl(window.location.href)) {
        return storedUsername;
    }
    if (accounts.length === 1 && accounts[0].username) {
        return accounts[0].username;
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
            <input id="pmNameInput" type="text" placeholder="Name (e.g., Work, Personal)" value="${existingName}" style="padding: 8px; margin-bottom: 15px; width: 100%; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px;" />
        ` : "";

        const usernameInputHTML = showUsernameInput ? `
            <input id="pmUsernameInput" type="text" placeholder="Username" value="${usernameValue}" style="padding: 8px; margin-bottom: 15px; width: 100%; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px;" />
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
        window.parent.postMessage({
            type: "PM_LOGIN",
            token,
            domain: currentDomain,
            username,
            password,
            accountName: accounts.length > 0 ? accounts[0].name : "",
            hasAccounts: accounts.length > 0
        }, "*");

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
    chrome.storage.local.set({
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
    chrome.storage.local.remove("pmPopupPending");
}

function isPopupPending() {
    return new Promise((resolve) => {
        chrome.storage.local.get("pmPopupPending", (result) => {
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
async function initExtension(accounts) {
    observeInputs(accounts);

    // Remember the last username typed on this domain so password-only
    // login steps (and the save prompt) know which account is logging in.
    document.addEventListener("input", (e) => {
        const t = e.target;
        if (t && t.matches &&
            t.matches("input[type='text'], input[type='email'], input[type='username'], input[type='tel']") &&
            t.value.trim()) {
            storeUsernameForLater(t.value.trim());
        }
    }, true);

    const pendingPopup = await isPopupPending();
    if (pendingPopup && !modalOpen) {
        modalOpen = true;
        const pendingDomain = pendingPopup.domain;
        const domainAccounts = await fetchAccounts(pendingDomain);
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

        const { username: rawUsername, password } = findLoginCredentials();
        if (!password) return;
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

            if (modalOpen || popupResolved) {
                event.source.postMessage({ type: "PM_LOGIN_RESULT", action: "ignore", token: data.token }, "*");
                return;
            }

            modalOpen = true;
            let domainAccounts = await fetchAccounts(data.domain);
            if (!domainAccounts.length) {
                domainAccounts = accounts;
            }
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

            event.source.postMessage({ type: "PM_LOGIN_RESULT", action: result.action, token: data.token }, "*");
        });
    }

    // Catch logins that navigate/redirect without a form submit event
    // (e.g. fetch + window.location, or form.submit() in JS), so the
    // save/update prompt still appears on the landing page.
    window.addEventListener("pagehide", () => {
        if (modalOpen || popupResolved) return;

        const { username: rawUsername, password } = findLoginCredentials();
        if (!password) return;
        const username = resolveUsername(rawUsername, accounts);
        if (rawUsername) storeUsernameForLater(rawUsername);
        if (findMatchingAccount(username, password, accounts)) return;

        setPopupPending({
            username,
            password,
            accountName: accounts.length > 0 ? accounts[0].name : "",
            hasAccounts: accounts.length > 0
        });

        // Relay from a subframe so the parent can show the prompt live.
        if (window !== window.top) {
            window.parent.postMessage({
                type: "PM_LOGIN",
                token: Math.random().toString(36).slice(2),
                domain: currentDomain,
                username,
                password,
                accountName: accounts.length > 0 ? accounts[0].name : "",
                hasAccounts: accounts.length > 0
            }, "*");
        }
    });
}

chrome.runtime.sendMessage(
    { action: "getCredentials", domain: window.location.hostname },
    (response) => {
        if (response && response.success) {
            try {
                let accounts = [];
                try {
                    accounts = JSON.parse(response.data);
                    if (!Array.isArray(accounts)) accounts = [];
                } catch (e) {
                    accounts = [];
                }
                initExtension(accounts);
            } catch (error) {
                console.log("Password Manager error:", error);
            }
        }
    }
);