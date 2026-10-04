function attachInput(input) {
    // Ignore extension UI elements
    if (!(input instanceof HTMLInputElement) || input.classList.contains("my-extension-ui")) return;
    const typedKind = typedAutofillKind(input);
    if (isTotpInput(input)) {
        createSecureTotpButton(input);
    } else if (typedKind) {
        createSecureTypedButton(input, typedKind);
    } else if (isCredentialInput(input)) {
        createSecureCredentialButton(input);
    } else {
        removeSecurePickerButton(input);
    }
    if (isUsableInput(input) && input.type === "password" && isNewPasswordInput(input)) {
        createGeneratorButton(input);
    }
}

function openRoots(root) {
    const roots = [root];
    if (root.shadowRoot) roots.push(...openRoots(root.shadowRoot));
    for (const candidate of root.querySelectorAll?.("*") || []) {
        if (candidate.shadowRoot) roots.push(...openRoots(candidate.shadowRoot));
    }
    return roots;
}

function attachToInputs(root = document) {
    for (const openRoot of openRoots(root)) {
        if (openRoot instanceof HTMLInputElement) attachInput(openRoot);
        openRoot.querySelectorAll?.("input").forEach(attachInput);
    }
}

// ===============================
// Observe DOM safely (no loop)
// ===============================
function observeInputs() {
    const pendingRoots = new Set();
    const observedRoots = new WeakSet();
    let attachScheduled = false;
    const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            if (mutation.type === "attributes" && mutation.target instanceof HTMLInputElement) {
                scheduleAttach(mutation.target);
            }
            for (const node of mutation.addedNodes) {
                if (node.nodeType === 1) scheduleAttach(node);
            }
        }
    });
    const observeRoot = root => {
        for (const openRoot of openRoots(root)) {
            if (observedRoots.has(openRoot)) continue;
            observedRoots.add(openRoot);
            observer.observe(openRoot, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: ["class", "style", "hidden", "type", "autocomplete", "disabled", "readonly"]
            });
        }
    };
    const scheduleAttach = root => {
        pendingRoots.add(root);
        if (attachScheduled) return;
        attachScheduled = true;
        requestAnimationFrame(() => {
            attachScheduled = false;
            for (const pending of pendingRoots) {
                attachToInputs(pending);
                observeRoot(pending);
            }
            pendingRoots.clear();
        });
    };

    // Initial run
    attachToInputs();
    observeRoot(document.body);
}
// ===============================
// Get domain from URL
// ===============================
