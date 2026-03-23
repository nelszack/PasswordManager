function createDropdownButton(input, accounts) {
    if (input.dataset.hasCredentialDropdown) return;
    input.dataset.hasCredentialDropdown = "true";

    // Create button
    const button = document.createElement("button");
    button.type = "button";
    button.innerText = "🔑";
    Object.assign(button.style, {
        position: "absolute",
        border: "none",
        background: "transparent",
        cursor: "pointer",
        fontSize: "16px",
        zIndex: "2147483647",
        padding: "0",
        margin: "0"
    });

    document.body.appendChild(button);

    // Position button relative to input
    function positionButton() {
        const rect = input.getBoundingClientRect();
        button.style.left = rect.right - 22 + "px";
        button.style.top = rect.top + rect.height / 2 - 15 + "px";
        button.style.top = rect.top + rect.height / 2 - 15 + "px";
    }

    positionButton();
    window.addEventListener("scroll", positionButton);
    window.addEventListener("resize", positionButton);

    // Create dropdown
    const menu = document.createElement("div");
    Object.assign(menu.style, {
        position: "absolute",
        background: "#fff",
        border: "1px solid #ccc",
        display: "none",
        zIndex: "2147483647",
        minWidth: "180px",
        boxShadow: "0 4px 12px rgba(0,0,0,0.25)"
    });

    document.body.appendChild(menu);

    function positionMenu() {
        const rect = button.getBoundingClientRect();
        menu.style.left = rect.left + "px";
        menu.style.top = rect.bottom + "px";
    }

    accounts.forEach(acc => {
        const item = document.createElement("div");
        item.innerText = acc.username;
        Object.assign(item.style, {
            padding: "8px 12px",
            cursor: "pointer"
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

    button.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();

        if (menu.style.display === "block") {
            menu.style.display = "none";
        } else {
            positionMenu();
            menu.style.display = "block";
        }
    });

    document.addEventListener("click", (e) => {
        if (!menu.contains(e.target) && e.target !== button) {
            menu.style.display = "none";
        }
    });
}

// ===============================
// Attach to all valid inputs
// ===============================
function attachToInputs(accounts) {
    if (!document.location.href.includes("auth") && !document.location.href.includes("login")) {
        return
    }
    const inputs = document.querySelectorAll(
        "input[type='text'], input[type='email'], input[type='password']"
    );

    inputs.forEach(input => {
        // Ignore extension UI elements
        if (input.classList.contains("my-extension-ui")) return;
        createDropdownButton(input, accounts);
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
    return accounts.find(acc =>
        acc.username === username && acc.password === password
    );
}

// ===============================
// Show custom prompt modal
// ===============================
let modalOpen = false;

function showPromptModal(title, message, showUpdateOption = false, oldUsername = "", oldPassword = "", showNameInput = false, existingName = "") {
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

        modal.innerHTML = `
            <h3 style="margin: 0 0 10px 0;">${title}</h3>
            <p style="margin: 0 0 15px 0; color: #666;">${message}</p>
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
            document.body.removeChild(overlay);
            cleanup();
            resolve({ action: "add", name });
        });

        const updateBtn = document.getElementById("pmUpdateBtn");
        if (updateBtn) {
            updateBtn.addEventListener("click", (e) => {
                e.preventDefault();
                e.stopPropagation();
                e.stopImmediatePropagation();
                const name = showNameInput ? document.getElementById("pmNameInput").value.trim() : existingName;
                document.body.removeChild(overlay);
                cleanup();
                resolve({ action: "update", name });
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
// Track popup state across pages
// ===============================
let popupResolved = false;
let currentDomain = window.location.hostname;

function setPopupPending(pendingData) {
    chrome.storage.local.set({
        pmPopupPending: {
            domain: currentDomain,
            username: pendingData.username,
            password: pendingData.password,
            accountName: pendingData.accountName,
            hasAccounts: pendingData.hasAccounts
        }
    });
}

function clearPopupPending() {
    chrome.storage.local.remove("pmPopupPending");
}

function isPopupPending() {
    return new Promise((resolve) => {
        chrome.storage.local.get("pmPopupPending", (result) => {
            if (result.pmPopupPending && result.pmPopupPending.domain === currentDomain) {
                resolve(result.pmPopupPending);
            } else {
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

    const pendingPopup = await isPopupPending();
    if (pendingPopup && !modalOpen) {
        modalOpen = true;
        const result = await showPromptModal(
            pendingPopup.hasAccounts ? "Credentials Mismatch" : "Save Credentials",
            pendingPopup.hasAccounts 
                ? `This doesn't match saved account "${pendingPopup.accountName || pendingPopup.username}". What would you like to do?`
                : "Would you like to save these credentials?",
            pendingPopup.hasAccounts,
            pendingPopup.hasAccounts ? pendingPopup.username : "",
            pendingPopup.hasAccounts ? pendingPopup.password : "",
            true,
            pendingPopup.accountName || ""
        );

        modalOpen = false;
        popupResolved = true;
        clearPopupPending();

        if (result.action === "add") {
            chrome.runtime.sendMessage({
                action: "saveCredentials",
                domain: currentDomain,
                username: pendingPopup.username,
                password: pendingPopup.password,
                name: result.name
            });
        } else if (result.action === "update") {
            chrome.runtime.sendMessage({
                action: "updateCredentials",
                domain: currentDomain,
                username: pendingPopup.username,
                password: pendingPopup.password,
                name: result.name,
            });
        }
        return;
    }

    document.addEventListener("submit", async (e) => {
        if (modalOpen || popupResolved) return;

        const { username, password } = findLoginCredentials();
        if (!username || !password) return;

        const match = findMatchingAccount(username, password, accounts);
        if (!match) {
            e.preventDefault();
            modalOpen = true;
            const domain = currentDomain;

            setPopupPending({
                username,
                password,
                accountName: accounts.length > 0 ? accounts[0].name : "",
                hasAccounts: accounts.length > 0
            });

            const result = await showPromptModal(
                accounts.length > 0 ? "Credentials Mismatch" : "Save Credentials",
                accounts.length > 0 
                    ? `This doesn't match saved account "${accounts[0].username}". What would you like to do?`
                    : "Would you like to save these credentials?",
                accounts.length > 0,
                accounts.length > 0 ? accounts[0].username : "",
                accounts.length > 0 ? accounts[0].password : "",
                true,
                accounts.length > 0 ? accounts[0].name : ""
            );

            modalOpen = false;
            popupResolved = true;
            clearPopupPending();

            if (result.action === "add") {
                chrome.runtime.sendMessage({
                    action: "saveCredentials",
                    domain: domain,
                    username: username,
                    password: password,
                    name: result.name
                });
                e.target.submit();
            } else if (result.action === "update") {
                chrome.runtime.sendMessage({
                    action: "updateCredentials",
                    domain: domain,
                    username: username,
                    password: password,
                    name: result.name,
                });
                e.target.submit();
            }
        }
    }, true);
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