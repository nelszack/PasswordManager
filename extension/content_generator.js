"use strict";
const { positionedButton, controlButton, setIcon, CONTROL_OFFSET } = require("./content_controls.js");
const PasswordManagerGenerator = require("./password_generator.js");
const { scopeInputs, credentialScope, isNewPasswordInput } = require("./content_detection.js");
module.exports.create = function create({ controls, bridge, credentials }) {
    const { registerPositionedControl } = controls;
    const { fillInput } = bridge;
    let pageGeneratorSettings = PasswordManagerGenerator.defaults;
    let pageGeneratorStorage = {};
    chrome.storage.local.get(["pmGenerator", "pmGeneratorsByOrigin"], result => {
        pageGeneratorStorage = result;
        pageGeneratorSettings = PasswordManagerGenerator.settingsForSite(pageGeneratorStorage, location.href);
    });
    const storageChanged = (changes, area) => {
        if (area !== "local") return;
        for (const key of ["pmGenerator", "pmGeneratorsByOrigin"])
            if (changes[key]) pageGeneratorStorage[key] = changes[key].newValue;
        pageGeneratorSettings = PasswordManagerGenerator.settingsForSite(pageGeneratorStorage, location.href);
    };
    chrome.storage.onChanged.addListener(storageChanged);
    function generatePagePassword(length) {
        return PasswordManagerGenerator.generate(
            length === undefined ? pageGeneratorSettings : { ...pageGeneratorSettings, length }
        );
    }

    const generatorControls = new WeakMap();

    function removeGeneratorButton(input) {
        generatorControls.get(input)?.remove();
    }

    function createGeneratorButton(input) {
        const existing = generatorControls.get(input);
        if (existing) {
            controls.schedulePosition();
            return;
        }

        const button = controlButton("sparkle", "Generate a strong password");
        if (!input.insertAdjacentElement?.("afterend", button)) document.body.appendChild(button);

        const positionButton = positionedButton(input, button, CONTROL_OFFSET);

        button.addEventListener("click", event => {
            if (!event.isTrusted) return;
            event.preventDefault();
            event.stopPropagation();
            const password = generatePagePassword();
            const fields = scopeInputs(credentialScope(input)).filter(isNewPasswordInput);
            const targets = fields.length > 0 ? fields : [input];
            targets.forEach(field => fillInput(field, password));
            credentials.lastInput = input;
            input.focus();
            button.title = "Strong password filled. Click again for a different one.";
            setIcon(button, "check");
            showToast(input, "Strong password filled. You’ll be asked to save it after signing up.");
            setTimeout(() => setIcon(button, "sparkle"), 2500);
        });

        const control = { remove: null };
        control.remove = registerPositionedControl(input, button, positionButton, () => {
            if (generatorControls.get(input) === control) generatorControls.delete(input);
        });
        generatorControls.set(input, control);
    }

    // Brief confirmation under the field; announced politely to screen readers.
    function showToast(input, message) {
        const rect = input.getBoundingClientRect();
        const toast = document.createElement("div");
        toast.className = "my-extension-ui";
        toast.setAttribute("role", "status");
        toast.textContent = message;
        Object.assign(toast.style, {
            position: "fixed",
            left: Math.max(8, rect.left) + "px",
            top: rect.bottom + 6 + "px",
            maxWidth: "320px",
            padding: "8px 12px",
            borderRadius: "8px",
            background: "#1f2a44",
            color: "#ffffff",
            font: "13px/1.4 system-ui, sans-serif",
            boxShadow: "0 4px 14px rgba(0,0,0,.25)",
            zIndex: "2147483647",
            pointerEvents: "none",
        });
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3500);
    }

    function dispose() {
        chrome.storage.onChanged.removeListener(storageChanged);
    }

    return { createGeneratorButton, removeGeneratorButton, dispose };
};
