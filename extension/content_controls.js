"use strict";
const {
    credentialFields,
    credentialScope,
    isElementVisible,
    isExtensionUi = () => false,
    markExtensionUi = element => element,
    withVisibilityCache = action => action(),
} = require("./content_detection.js");
module.exports.create = function create({ bridge, credentials, autofill }) {
    const { fillInput, openSecurePicker } = bridge;
    const { storeUsernameForLater } = credentials;
    const { fillTypedItem, typedFillContext } = autofill;
    const lifecycle = new AbortController();
    // Reposition secure picker and generator buttons as the page layout changes.
    const positionedControls = new Set();
    let listenersStarted = false;
    let disposed = false;
    let repositionScheduled = false;
    // Scrolling moves controls with their fields; only layout changes can move a
    // site's own icon over a field, so only they repeat the overlay hit test.
    let layoutPending = false;
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
        startListeners();
        controlResizeObserver?.observe(input);
        schedulePosition();
        return record.remove;
    }

    function reposition(layout) {
        if (disposed || !positionedControls.size) return;
        layoutPending ||= layout;
        if (repositionScheduled) return;
        repositionScheduled = true;
        requestAnimationFrame(() => {
            repositionScheduled = false;
            const full = layoutPending;
            layoutPending = false;
            if (disposed) return;
            const writes = [];
            withVisibilityCache(() => {
                for (const control of positionedControls) {
                    if (!control.input.isConnected) {
                        control.remove();
                        continue;
                    }
                    if (control.position.measure) writes.push(control.position.measure(full));
                    else writes.push(control.position);
                }
            });
            for (const write of writes) write();
        });
    }
    const schedulePosition = () => reposition(true);

    // Page mutations reach controls through the content observer, which watches
    // the document and every registered open shadow root.
    function startListeners() {
        if (listenersStarted) return;
        listenersStarted = true;
        window.addEventListener("load", schedulePosition, { signal: lifecycle.signal });
        window.addEventListener("scroll", () => reposition(false), { capture: true, signal: lifecycle.signal });
        window.addEventListener("resize", schedulePosition, { signal: lifecycle.signal });
        controlResizeObserver = new ResizeObserver(schedulePosition);
        for (const control of positionedControls) controlResizeObserver.observe(control.input);
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

        const { host, button } = controlButton(icon, title);
        // Keep keyboard traversal beside the field the control belongs to.
        if (!input.insertAdjacentElement?.("afterend", host)) document.body.appendChild(host);
        const positionButton = positionedButton(input, host, CONTROL_OFFSET);
        const control = { kind, remove: null };
        control.remove = registerPositionedControl(input, host, positionButton, () => {
            if (securePickerControls.get(input) === control) {
                securePickerControls.delete(input);
            }
        });
        securePickerControls.set(input, control);
        button.addEventListener("click", event => {
            if (!event.isTrusted) return;
            event.preventDefault();
            event.stopPropagation();
            // Failures are shown on the button itself.
            control.activate().catch(() => {});
        });
        // `select` supplies the selection; by default the secure picker window.
        control.activate = async (select = () => openSecurePicker(kind)) => {
            try {
                const scope = selectionScope();
                const selection = await select();
                if (selection) onSelection(selection, scope);
                return Boolean(selection);
            } catch (error) {
                setIcon(button, "warning");
                button.title = error?.message || "Could not open secure picker";
                button.setAttribute("aria-label", `${title}: ${button.title}`);
                setTimeout(() => {
                    setIcon(button, icon);
                    button.title = title;
                    button.setAttribute("aria-label", title);
                }, 5000);
                // Say why in words too, below the field, so it is seen and announced.
                const rect = input.getBoundingClientRect?.();
                if (rect && document.body) {
                    const toast = toastHost(button.title, Math.max(8, rect.left), rect.bottom + 6);
                    document.body.appendChild(toast);
                    setTimeout(() => toast.remove(), 5000);
                }
                throw error;
            }
        };
    }

    // The focused field's login control, or else the first visible one.
    function loginControl(focused, anyKind = true) {
        const own = focused ? securePickerControls.get(focused) : undefined;
        if (own && (anyKind || own.kind === "login")) return own;
        for (const record of positionedControls) {
            const candidate = securePickerControls.get(record.input);
            if (candidate?.kind === "login" && isElementVisible(record.input)) return candidate;
        }
        return undefined;
    }

    // Keyboard shortcut: open the picker for the focused field, or else for the
    // first visible login field on the page. Returns whether a picker opened.
    function activateShortcut(focused) {
        const control = loginControl(focused);
        if (!control) return false;
        control.activate().catch(() => {});
        return true;
    }

    // Fill a login chosen in the toolbar popup. `claim` fetches it from the
    // extension; resolves to whether a login form was filled.
    async function fillFromPopup(focused, claim) {
        const control = loginControl(focused, false);
        if (!control) return false;
        return control.activate(claim);
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
        createSecurePickerButton(input, "totp", "clock", "Choose one-time code", totp => {
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
        controlResizeObserver?.disconnect();
        for (const control of positionedControls) control.remove();
    }

    return {
        createSecureCredentialButton,
        createSecureTotpButton,
        createSecureTypedButton,
        removeSecurePickerButton,
        activateShortcut,
        fillFromPopup,
        registerPositionedControl,
        schedulePosition,
        layoutChanged: schedulePosition,
        accountUsername,
        dispose,
    };
};

const CONTROL_SIZE = 28;
const CONTROL_OFFSET = 30;
// Feather-style outline icons (24×24, stroke = currentColor) so controls look the
// same on every OS instead of depending on emoji fonts.
const ICONS = {
    key: [
        "M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4",
    ],
    clock: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z", "M12 6v6l4 2"],
    card: ["M3 4h18a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z", "M1 10h22"],
    person: ["M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2", "M12 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8z"],
    sparkle: [
        "M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z",
        "M19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8z",
    ],
    check: ["M20 6L9 17l-5-5"],
    warning: [
        "M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z",
        "M12 9v4",
        "M12 17h.01",
    ],
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
// In-page UI lives in a closed shadow root under an autonomous custom element:
// it stays out of form.elements and page selectors, and page styles cannot
// restyle the button. Browser tests set the hook below from a test-only content
// script so Playwright can reach the controls; pages cannot set content-script
// globals.
const UI_TAG = "pm-field-control";
// Important :host rules beat page !important rules on the host. They must not
// declare display/left/top/pointer-events: those are written inline (also
// !important), and a shadow-context !important rule would override them.
const HOST_STYLE =
    ":host{position:fixed!important;right:auto!important;bottom:auto!important;width:auto!important;height:auto!important;margin:0!important;padding:0!important;border:0!important;float:none!important;transform:none!important;filter:none!important;clip-path:none!important;opacity:1!important;visibility:visible!important;z-index:2147483647!important;}";
const BUTTON_STYLE = `button{all:initial;box-sizing:border-box;display:flex;align-items:center;justify-content:center;width:${CONTROL_SIZE}px;height:${CONTROL_SIZE}px;padding:0;margin:0;border:1px solid #c7d3f5;border-radius:6px;background:#eef2fd;color:#2850be;cursor:pointer;box-shadow:0 1px 2px rgba(0,0,0,.12);}button:hover{background:#dbe4fb;}button:focus-visible{outline:2px solid #2850be;outline-offset:2px;}svg{display:block;pointer-events:none;}@media (prefers-color-scheme:dark){button{background:#253252;border-color:#3d4d78;color:#9cb7ff;}button:hover{background:#2f3d63;}button:focus-visible{outline-color:#9cb7ff;}}@media (forced-colors:active){button{background:ButtonFace;border-color:ButtonText;color:ButtonText;forced-color-adjust:none;}button:focus-visible{outline-color:Highlight;}}`;
const TOAST_STYLE =
    "div{max-width:320px;padding:8px 12px;border-radius:8px;background:#1f2a44;color:#fff;font:13px/1.4 system-ui,sans-serif;box-shadow:0 4px 14px rgba(0,0,0,.25);}";
function setImportantStyles(element, values) {
    for (const [key, value] of Object.entries(values)) {
        if (element.style.getPropertyValue(key) !== value || element.style.getPropertyPriority(key) !== "important")
            element.style.setProperty(key, value, "important");
    }
}
function uiHost(css) {
    const host = document.createElement(UI_TAG);
    markExtensionUi(host);
    const root = host.attachShadow({ mode: globalThis.__pmTestOpenShadowRoots === true ? "open" : "closed" });
    const style = document.createElement("style");
    style.textContent = HOST_STYLE + css;
    root.appendChild(style);
    setImportantStyles(host, { display: "none" });
    return { host, root };
}
// A small branded chip that reads clearly on light and dark fields.
function controlButton(icon, title) {
    const { host, root } = uiHost(BUTTON_STYLE);
    const button = document.createElement("button");
    button.type = "button";
    button.title = title;
    button.setAttribute("aria-label", title);
    setIcon(button, icon);
    root.appendChild(button);
    return { host, button };
}
// A brief status message, announced politely to screen readers.
function toastHost(message, left, top) {
    const { host, root } = uiHost(TOAST_STYLE);
    const toast = document.createElement("div");
    toast.setAttribute("role", "status");
    toast.textContent = message;
    root.appendChild(toast);
    setImportantStyles(host, { display: "block", left: left + "px", top: top + "px", "pointer-events": "none" });
    return host;
}
// Sites often place their own icon (show password, clear) at the field's right
// edge. When something other than the field is on top there, step left of it.
// Returns null when the probe point is off screen, where no hit test is possible.
function overlayShift(input, left, top) {
    const x = left + CONTROL_SIZE / 2;
    const y = top + CONTROL_SIZE / 2;
    const { innerWidth = Infinity, innerHeight = Infinity } = globalThis.window || {};
    if (x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) return null;
    const hits = globalThis.document?.elementsFromPoint?.(x, y);
    const hit = hits?.find(element => !isExtensionUi(element));
    if (!hit || hit === input || hit.contains?.(input) || input.getRootNode?.()?.host === hit) return 0;
    return CONTROL_SIZE + 4;
}

// Return deferred writes so callers can finish all style/geometry reads first.
// The overlay hit test is cached and repeated only for layout changes.
function positionedButton(input, host, offset) {
    let shift = null;
    const measure = (layout = true) => {
        const rect = isElementVisible(input) ? input.getBoundingClientRect() : null;
        let values = { display: "none" };
        if (rect?.width && rect?.height) {
            const top = rect.top + rect.height / 2 - CONTROL_SIZE / 2;
            const left = rect.right - offset;
            if (layout || shift === null) shift = overlayShift(input, left, top);
            const shifted = Math.max(rect.left ?? -Infinity, left - (shift ?? 0));
            values = { display: "block", left: shifted + "px", top: top + "px" };
        }
        return () => setImportantStyles(host, values);
    };
    const position = () => measure()();
    position.measure = measure;
    return position;
}
module.exports.positionedButton = positionedButton;
module.exports.controlButton = controlButton;
module.exports.toastHost = toastHost;
module.exports.setIcon = setIcon;
module.exports.CONTROL_OFFSET = CONTROL_OFFSET;
