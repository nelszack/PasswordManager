"use strict";
const {
    isUsableInput,
    credentialFields,
    credentialScope,
    withVisibilityCache = action => action(),
} = require("./content_detection.js");
module.exports.create = function create({ bridge, credentials, autofill }) {
    const { fillInput, openSecurePicker } = bridge;
    const { storeUsernameForLater } = credentials;
    const { fillTypedItem, typedFillContext } = autofill;
    const lifecycle = new AbortController();
    let layoutObserver;
    // Reposition secure picker and generator buttons as the page layout changes.
    const positionedControls = new Set();
    let layoutObserverStarted = false;
    let disposed = false;
    let schedulePosition = () => {};
    let repositionScheduled = false;
    let controlResizeObserver = null;

    function registerPositionedControl(input, button, position, onRemove = () => {}) {
        const record = {
            input,
            button,
            position,
            remove() {
                positionedControls.delete(record);
                button.remove();
                if (![...positionedControls].some(control => control.input === input)) {
                    controlResizeObserver?.unobserve(input);
                }
                onRemove();
            },
        };
        positionedControls.add(record);
        startLayoutObserver();
        controlResizeObserver?.observe(input);
        schedulePosition();
        return record.remove;
    }

    function startLayoutObserver() {
        if (layoutObserverStarted) return;
        layoutObserverStarted = true;

        const reposition = () => {
            if (disposed || repositionScheduled) return;
            repositionScheduled = true;
            requestAnimationFrame(() => {
                repositionScheduled = false;
                if (disposed) return;
                const writes = [];
                withVisibilityCache(() => {
                    for (const control of positionedControls) {
                        if (!control.input.isConnected) {
                            control.remove();
                            continue;
                        }
                        if (control.position.measure) writes.push(control.position.measure());
                        else writes.push(control.position);
                    }
                });
                for (const write of writes) write();
            });
        };

        schedulePosition = reposition;
        window.addEventListener("load", reposition, { signal: lifecycle.signal });
        window.addEventListener("scroll", reposition, { capture: true, signal: lifecycle.signal });
        window.addEventListener("resize", reposition, { signal: lifecycle.signal });

        controlResizeObserver = new ResizeObserver(reposition);
        for (const control of positionedControls) controlResizeObserver.observe(control.input);

        // Ancestor visibility/layout changes can move or hide controls without
        // changing the inputs themselves. Ignore our own style writes to avoid
        // scheduling another layout frame after every reposition.
        layoutObserver = new MutationObserver(mutations => {
            if (
                mutations.some(
                    mutation =>
                        mutation.type !== "attributes" || !mutation.target.classList?.contains("my-extension-ui")
                )
            )
                reposition();
        });
        layoutObserver.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ["class", "style", "hidden", "open"],
        });
    }

    const securePickerControls = new WeakMap();

    function removeSecurePickerButton(input) {
        securePickerControls.get(input)?.remove();
    }

    function createSecurePickerButton(input, kind, icon, title, onSelection, selectionScope = () => undefined) {
        const existing = securePickerControls.get(input);
        if (existing?.kind === kind) {
            schedulePosition();
            return;
        }
        existing?.remove();

        const button = controlButton(icon, title);
        // Keep keyboard traversal beside the field the control belongs to.
        if (!input.insertAdjacentElement?.("afterend", button)) document.body.appendChild(button);
        const positionButton = positionedButton(input, button, CONTROL_OFFSET);
        const control = { kind, remove: null };
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
            try {
                const scope = selectionScope();
                const selection = await openSecurePicker(kind);
                if (selection) onSelection(selection, scope);
            } catch (error) {
                setIcon(button, "warning");
                button.title = error?.message || "Could not open secure picker";
                button.setAttribute("aria-label", `${title}: ${button.title}`);
                setTimeout(() => {
                    setIcon(button, icon);
                    button.title = title;
                    button.setAttribute("aria-label", title);
                }, 5000);
            }
        });
    }

    function createSecureCredentialButton(input) {
        createSecurePickerButton(
            input,
            "login",
            "key",
            "Choose saved credentials",
            (account, scope) => {
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
            },
            () => credentialScope(input)
        );
    }

    function createSecureTotpButton(input) {
        createSecurePickerButton(input, "totp", "clock", "Choose authenticator code", totp => {
            fillInput(input, totp.code);
            input.focus();
        });
    }

    function createSecureTypedButton(input, kind) {
        createSecurePickerButton(
            input,
            kind,
            kind === "payment-card" ? "card" : "person",
            kind === "payment-card" ? "Choose payment card" : "Choose identity",
            (item, scope) => fillTypedItem(input, item, scope),
            () => typedFillContext(input)
        );
    }

    function accountUsername(account) {
        return account.username || "";
    }

    function dispose() {
        disposed = true;
        lifecycle.abort();
        layoutObserver?.disconnect();
        controlResizeObserver?.disconnect();
        for (const control of positionedControls) control.remove();
    }

    return {
        createSecureCredentialButton,
        createSecureTotpButton,
        createSecureTypedButton,
        removeSecurePickerButton,
        registerPositionedControl,
        schedulePosition: () => schedulePosition(),
        accountUsername,
        dispose,
    };
};

const CONTROL_SIZE = 28;
const CONTROL_OFFSET = 30;
// Feather-style outline icons (24×24, stroke = currentColor) so controls look the
// same on every OS instead of depending on emoji fonts.
const ICONS = {
    key: ["M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"],
    clock: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z", "M12 6v6l4 2"],
    card: ["M3 4h18a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z", "M1 10h22"],
    person: ["M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2", "M12 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8z"],
    sparkle: ["M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z", "M19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8z"],
    check: ["M20 6L9 17l-5-5"],
    warning: ["M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z", "M12 9v4", "M12 17h.01"],
};
function setIcon(button, name) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    for (const [key, value] of Object.entries({
        viewBox: "0 0 24 24",
        width: "16",
        height: "16",
        fill: "none",
        stroke: "currentColor",
        "stroke-width": "2",
        "stroke-linecap": "round",
        "stroke-linejoin": "round",
        "aria-hidden": "true",
        focusable: "false",
    }))
        svg.setAttribute(key, value);
    for (const d of ICONS[name] || ICONS.key) {
        const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
        path.setAttribute("d", d);
        svg.appendChild(path);
    }
    button.replaceChildren(svg);
    button.dataset.icon = name;
}
// A small branded chip that reads clearly on light and dark fields.
function controlButton(icon, title) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "my-extension-ui";
    button.title = title;
    button.setAttribute("aria-label", title);
    Object.assign(button.style, {
        position: "fixed",
        display: "none",
        alignItems: "center",
        justifyContent: "center",
        boxSizing: "border-box",
        width: CONTROL_SIZE + "px",
        height: CONTROL_SIZE + "px",
        minWidth: CONTROL_SIZE + "px",
        minHeight: CONTROL_SIZE + "px",
        padding: "0",
        margin: "0",
        border: "1px solid #c7d3f5",
        borderRadius: "6px",
        background: "#eef2fd",
        color: "#2850be",
        cursor: "pointer",
        zIndex: "2147483647",
        boxShadow: "0 1px 2px rgba(0,0,0,.12)",
    });
    button.addEventListener("mouseenter", () => (button.style.background = "#dbe4fb"));
    button.addEventListener("mouseleave", () => (button.style.background = "#eef2fd"));
    setIcon(button, icon);
    return button;
}
// Sites often place their own icon (show password, clear) at the field's right
// edge. When something other than the field is on top there, step left of it.
function overlayShift(input, left, top) {
    const hits = globalThis.document?.elementsFromPoint?.(left + CONTROL_SIZE / 2, top + CONTROL_SIZE / 2);
    const hit = hits?.find(element => !element.classList?.contains("my-extension-ui"));
    if (!hit || hit === input || hit.contains?.(input) || input.getRootNode?.()?.host === hit) return 0;
    return CONTROL_SIZE + 4;
}

// Return deferred writes so callers can finish all style/geometry reads first.
function positionedButton(input, button, offset) {
    const { isElementVisible } = require("./content_detection.js");
    const measure = () => {
        const rect = isElementVisible(input) ? input.getBoundingClientRect() : null;
        let values = { display: "none" };
        if (rect?.width && rect?.height) {
            const top = rect.top + rect.height / 2 - CONTROL_SIZE / 2;
            const left = rect.right - offset;
            const shifted = Math.max(rect.left ?? -Infinity, left - overlayShift(input, left, top));
            values = { display: "flex", left: shifted + "px", top: top + "px" };
        }
        return () => {
            for (const [key, value] of Object.entries(values)) {
                if (button.style[key] !== value) button.style[key] = value;
            }
        };
    };
    const position = () => measure()();
    position.measure = measure;
    return position;
}
module.exports.positionedButton = positionedButton;
module.exports.controlButton = controlButton;
module.exports.setIcon = setIcon;
module.exports.CONTROL_OFFSET = CONTROL_OFFSET;
