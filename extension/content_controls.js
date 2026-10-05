// Reposition secure picker and generator buttons as the page layout changes.
const positionedControls = new Set();
let layoutObserverStarted = false;
let repositionScheduled = false;
let controlResizeObserver = null;

function registerPositionedControl(input, button, position, onRemove = () => {}) {
    const record = { input, button, position, remove() {
        positionedControls.delete(record);
        button.remove();
        if (![...positionedControls].some(control => control.input === input)) {
            controlResizeObserver?.unobserve(input);
        }
        onRemove();
    } };
    positionedControls.add(record);
    startLayoutObserver();
    controlResizeObserver?.observe(input);
    return record.remove;
}

function startLayoutObserver() {
    if (layoutObserverStarted) return;
    layoutObserverStarted = true;

    const reposition = () => {
        if (repositionScheduled) return;
        repositionScheduled = true;
        requestAnimationFrame(() => {
            repositionScheduled = false;
            for (const control of positionedControls) {
                if (!control.input.isConnected) {
                    control.remove();
                    continue;
                }
                control.position();
            }
        });
    };

    window.addEventListener("load", reposition);
    window.addEventListener("scroll", reposition, true);
    window.addEventListener("resize", reposition);

    controlResizeObserver = new ResizeObserver(reposition);
    for (const control of positionedControls) controlResizeObserver.observe(control.input);

    // Ancestor visibility/layout changes can move or hide controls without
    // changing the inputs themselves. Ignore our own style writes to avoid
    // scheduling another layout frame after every reposition.
    new MutationObserver(mutations => {
        if (mutations.some(mutation => mutation.type !== "attributes"
            || !mutation.target.classList?.contains("my-extension-ui"))) reposition();
    }).observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["class", "style", "hidden", "open"]
    });
}

const securePickerControls = new WeakMap();

function removeSecurePickerButton(input) {
    securePickerControls.get(input)?.remove();
}

function createSecurePickerButton(input, kind, icon, title, onSelection) {
    const existing = securePickerControls.get(input);
    if (existing?.kind === kind) {
        existing.position();
        return;
    }
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
    const control = { kind, position: positionButton, remove: null };
    control.remove = registerPositionedControl(input, button, positionButton, () => {
        if (securePickerControls.get(input) === control) {
            securePickerControls.delete(input);
        }
    });
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
