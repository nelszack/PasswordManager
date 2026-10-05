function attachInput(input, formUsernames) {
    // Ignore extension UI elements
    if (!(input instanceof HTMLInputElement) || input.classList.contains("my-extension-ui")) return;
    const typedKind = typedAutofillKind(input);
    if (isTotpInput(input)) {
        createSecureTotpButton(input);
    } else if (typedKind) {
        createSecureTypedButton(input, typedKind);
    } else if (isCredentialInput(input, formUsernames)) {
        createSecureCredentialButton(input);
    } else {
        removeSecurePickerButton(input);
    }
    if (isUsableInput(input) && input.type === "password" && isNewPasswordInput(input)) {
        createGeneratorButton(input);
    } else {
        removeGeneratorButton(input);
    }
}

// Visit each light DOM / open shadow DOM subtree once for both discovery and
// observation. No credentials are fetched during this scan.
function attachToInputs(root = document, observeRoot = () => {}) {
    const roots = [root];
    // Form classification is shared within this scan, then discarded so later
    // DOM changes and user interactions always inspect the current fields.
    const formUsernames = new WeakMap();
    for (let index = 0; index < roots.length; index++) {
        const openRoot = roots[index];
        observeRoot(openRoot);
        if (openRoot instanceof HTMLInputElement) attachInput(openRoot, formUsernames);
        if (openRoot.shadowRoot) roots.push(openRoot.shadowRoot);
        for (const candidate of openRoot.querySelectorAll?.("*") || []) {
            if (candidate instanceof HTMLInputElement) attachInput(candidate, formUsernames);
            if (candidate.shadowRoot) roots.push(candidate.shadowRoot);
        }
    }
}

// Follow shadow hosts too: Node.contains does not cross shadow boundaries.
function coveredByPendingRoot(root, pendingRoots) {
    for (let parent = root.parentNode || root.host; parent; parent = parent.parentNode || parent.host) {
        if (pendingRoots.has(parent)) return true;
    }
    return false;
}

function observeInputs() {
    const pendingRoots = new Set();
    const observedRoots = new WeakSet();
    let attachScheduled = false;
    const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            if (mutation.type === "attributes") {
                if (mutation.target.classList?.contains("my-extension-ui")) continue;
                if (mutation.target instanceof HTMLInputElement
                    || ["class", "style", "hidden", "open"].includes(mutation.attributeName)) {
                    scheduleAttach(mutation.target);
                }
            }
            for (const node of mutation.addedNodes) {
                if (node.nodeType === 1) scheduleAttach(node);
            }
        }
    });
    const observeRoot = root => {
        if (observedRoots.has(root)) return;
        observedRoots.add(root);
        observer.observe(root, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ["class", "style", "hidden", "open", "type", "autocomplete", "disabled", "readonly"]
        });
    };
    const scheduleAttach = root => {
        pendingRoots.add(root);
        if (attachScheduled) return;
        attachScheduled = true;
        requestAnimationFrame(() => {
            attachScheduled = false;
            for (const pending of pendingRoots) {
                if (!pending.isConnected || coveredByPendingRoot(pending, pendingRoots)) continue;
                attachToInputs(pending, observeRoot);
            }
            pendingRoots.clear();
        });
    };

    attachToInputs(document, observeRoot);
}
