"use strict";
const { isUsableInput, isElementVisible, credentialFields, credentialScope } = require("./content_detection.js");
module.exports.create = function create({ bridge, credentials, autofill }) {
    const { fillInput, openSecurePicker } = bridge;
    const { storeUsernameForLater } = credentials;
    const { fillTypedItem, typedFillContext } = autofill;
    const lifecycle = new AbortController();
    let layoutObserver;
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

        window.addEventListener("load", reposition, { signal: lifecycle.signal });
        window.addEventListener("scroll", reposition, { capture: true, signal: lifecycle.signal });
        window.addEventListener("resize", reposition, { signal: lifecycle.signal });

        controlResizeObserver = new ResizeObserver(reposition);
        for (const control of positionedControls) controlResizeObserver.observe(control.input);

        // Ancestor visibility/layout changes can move or hide controls without
        // changing the inputs themselves. Ignore our own style writes to avoid
        // scheduling another layout frame after every reposition.
        layoutObserver = new MutationObserver(mutations => {
            if (mutations.some(mutation => mutation.type !== "attributes"
                || !mutation.target.classList?.contains("my-extension-ui"))) reposition();
        });
        layoutObserver.observe(document.body, {
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

    function createSecurePickerButton(input, kind, icon, title, onSelection, selectionScope = () => undefined) {
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
            fontSize: "16px", zIndex: "2147483647", padding: "0", margin: "0", display: "none",
            width: "28px", height: "28px", minWidth: "28px", minHeight: "28px", boxSizing: "border-box"
        });
        // Keep keyboard traversal beside the field the control belongs to.
        if (!input.insertAdjacentElement?.("afterend", button)) document.body.appendChild(button);
        const positionButton = () => {
            if (!isElementVisible(input)) {
                button.style.display = "none";
                return;
            }
            const rect = input.getBoundingClientRect();
            button.style.display = rect.width && rect.height ? "" : "none";
            button.style.left = rect.right - 30 + "px";
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
                const scope = selectionScope();
                const selection = await openSecurePicker(kind);
                if (selection) onSelection(selection, scope);
            } catch (error) {
                button.innerText = "⚠️";
                button.title = error?.message || "Could not open secure picker";
                button.setAttribute("aria-label", `${title}: ${button.title}`);
                setTimeout(() => {
                    button.innerText = originalIcon;
                    button.title = title;
                    button.setAttribute("aria-label", title);
                }, 5000);
            }
        });
    }

    function createSecureCredentialButton(input) {
        createSecurePickerButton(input, "login", "🔑", "Choose saved credentials", (account, scope) => {
            if (!scope.isConnected) return;
            let fields = credentialFields(input, scope);
            storeUsernameForLater(accountUsername(account).trim());
            fillInput(fields.usernameField, accountUsername(account));
            // Site input handlers may replace fields synchronously. Stay within
            // the original scope and resolve the live password after those run.
            if (!scope.isConnected) return;
            fields = credentialFields(input, scope);
            fillInput(fields.passwordField, account.password);
            (fields.passwordField || fields.usernameField)?.focus();
        }, () => credentialScope(input));
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
            (item, scope) => fillTypedItem(input, item, scope),
            () => typedFillContext(input)
        );
    }

    function accountUsername(account) {
        return account.username || "";
    }

    function dispose() {
        lifecycle.abort(); layoutObserver?.disconnect(); controlResizeObserver?.disconnect();
        for (const control of positionedControls) control.remove();
    }

    return { createSecureCredentialButton, createSecureTotpButton, createSecureTypedButton, removeSecurePickerButton, registerPositionedControl, accountUsername, dispose };
};
