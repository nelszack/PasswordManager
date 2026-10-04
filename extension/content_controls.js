// ===============================
// Track dropdowns so they can be repositioned
// as the page loads / layout changes
// ===============================
const dropdownRegistry = new Set();
let layoutObserverStarted = false;
let repositionScheduled = false;
let controlResizeObserver = null;

function registerPositionedControl(input, button, menu, position, outsideClick = null) {
    const record = { input, button, menu, position, outsideClick };
    dropdownRegistry.add(record);
    startLayoutObserver();
    controlResizeObserver?.observe(input);
    return () => {
        dropdownRegistry.delete(record);
        button.remove();
        menu?.remove();
        if (![...dropdownRegistry].some(control => control.input === input)) {
            controlResizeObserver?.unobserve(input);
        }
    };
}

function startLayoutObserver() {
    if (layoutObserverStarted) return;
    layoutObserverStarted = true;

    const reposition = () => {
        if (repositionScheduled) return;
        repositionScheduled = true;
        requestAnimationFrame(() => {
            repositionScheduled = false;
            for (const control of dropdownRegistry) {
                if (!control.input.isConnected) {
                    control.button.remove();
                    control.menu?.remove();
                    controlResizeObserver?.unobserve(control.input);
                    dropdownRegistry.delete(control);
                    continue;
                }
                control.position();
            }
        });
    };

    window.addEventListener("load", reposition);
    window.addEventListener("scroll", reposition, true);
    window.addEventListener("resize", reposition);
    document.addEventListener("click", event => {
        for (const control of dropdownRegistry) control.outsideClick?.(event);
    });

    controlResizeObserver = new ResizeObserver(reposition);
    for (const control of dropdownRegistry) controlResizeObserver.observe(control.input);

    // Child insertion can move controls without changing their own dimensions.
    // Attribute changes are handled by the focused input observer below.
    new MutationObserver(reposition).observe(document.body, {
        childList: true,
        subtree: true
    });
}

const securePickerControls = new WeakMap();

function removeSecurePickerButton(input) {
    securePickerControls.get(input)?.remove();
}

function createSecurePickerButton(input, kind, icon, title, onSelection) {
    const existing = securePickerControls.get(input);
    if (existing?.kind === kind) return;
    existing?.remove();

    const button = document.createElement("button");
    button.type = "button";
    button.className = "my-extension-ui";
    button.innerText = icon;
    button.title = title;
    button.setAttribute("aria-label", title);
    Object.assign(button.style, {
        position: "fixed", border: "none", background: "transparent", cursor: "pointer",
        fontSize: "16px", zIndex: "2147483647", padding: "0", margin: "0", display: "none"
    });
    document.body.appendChild(button);
    const positionButton = () => {
        if (!isElementVisible(input)) {
            button.style.display = "none";
            return;
        }
        const rect = input.getBoundingClientRect();
        button.style.display = rect.width && rect.height ? "" : "none";
        button.style.left = rect.right - 24 + "px";
        button.style.top = rect.top + rect.height / 2 - 14 + "px";
    };
    positionButton();
    const unregister = registerPositionedControl(input, button, null, positionButton, () => {});
    const control = {
        kind,
        remove() {
            unregister();
            if (securePickerControls.get(input) === control) {
                securePickerControls.delete(input);
            }
        }
    };
    securePickerControls.set(input, control);
    button.addEventListener("click", async event => {
        if (!event.isTrusted) return;
        event.preventDefault();
        event.stopPropagation();
        const originalIcon = button.innerText;
        try {
            const selection = await openSecurePicker(kind);
            if (selection) onSelection(selection);
        } catch (error) {
            button.innerText = "⚠️";
            button.title = error?.message || "Could not open secure picker";
            setTimeout(() => {
                button.innerText = originalIcon;
                button.title = title;
            }, 5000);
        }
    });
}

function createSecureCredentialButton(input) {
    createSecurePickerButton(input, "login", "🔑", "Choose saved credentials", account => {
        const fields = credentialFields(input);
        fillInput(fields.usernameField, accountUsername(account));
        fillInput(fields.passwordField, account.password);
        (fields.passwordField || fields.usernameField)?.focus();
    });
}

function createSecureTotpButton(input) {
    createSecurePickerButton(input, "totp", "🔐", "Choose authenticator code", totp => {
        fillInput(input, totp.code);
        input.focus();
    });
}

function createSecureTypedButton(input, kind) {
    createSecurePickerButton(
        input,
        kind,
        kind === "payment-card" ? "💳" : "👤",
        kind === "payment-card" ? "Choose payment card" : "Choose identity",
        item => fillTypedItem(input, item)
    );
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
    const closeOnOutsideClick = (e) => {
        if (!menu.contains(e.target) && e.target !== button) menu.style.display = "none";
    };
    registerPositionedControl(input, button, menu, positionButton, closeOnOutsideClick);

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
                if (!e.isTrusted) return;
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
        if (!e.isTrusted) return;
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
                if (!event.isTrusted) return;
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
    const closeOnOutsideClick = event => {
        if (!menu.contains(event.target) && event.target !== button) menu.style.display = "none";
    };
    registerPositionedControl(input, button, menu, positionButton, closeOnOutsideClick);

    button.addEventListener("click", async (event) => {
        if (!event.isTrusted) return;
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

}

// Generate locally with the browser CSPRNG. Every generated password contains
// upper/lowercase letters, a digit, and a symbol; no secret crosses an extension
// or native-messaging boundary until the user chooses to save the form.
