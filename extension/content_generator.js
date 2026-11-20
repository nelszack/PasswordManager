"use strict";
const { positionedButton, controlButton, toastHost, setIcon, CONTROL_OFFSET } = require("./content_controls.js");
const PasswordManagerGenerator = require("./password_generator.js");
const { scopeInputs, credentialScope, isNewPasswordInput } = require("./content_detection.js");
module.exports.create = function create({ controls, bridge, credentials }) {
    const { registerPositionedControl } = controls;
    const { fillInput } = bridge;
    let pageGeneratorSettings = PasswordManagerGenerator.defaults;
    let pageGeneratorStorage = null;
    let disposed = false;
    const storageChanged = (changes, area) => {
        if (area !== "local" || !pageGeneratorStorage) return;
        for (const key of ["pmGenerator", "pmGeneratorsByOrigin"])
            if (changes[key]) pageGeneratorStorage[key] = changes[key].newValue;
        pageGeneratorSettings = PasswordManagerGenerator.settingsForSite(pageGeneratorStorage, location.href);
    };
    // Most frames never show a generator. Read site settings only once one does.
    function loadSettings() {
        if (pageGeneratorStorage || disposed) return;
        pageGeneratorStorage = {};
        chrome.storage.onChanged.addListener(storageChanged);
        chrome.storage.local.get(["pmGenerator", "pmGeneratorsByOrigin"], result => {
            if (disposed) return;
            // Changes reported while the read was pending are newer than its result.
            pageGeneratorStorage = { ...result, ...pageGeneratorStorage };
            pageGeneratorSettings = PasswordManagerGenerator.settingsForSite(pageGeneratorStorage, location.href);
        });
    }
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
        loadSettings();

        const { host, button } = controlButton("sparkle", "Generate a strong password");
        if (!input.insertAdjacentElement?.("afterend", host)) document.body.appendChild(host);

        const positionButton = positionedButton(input, host, CONTROL_OFFSET);

        button.addEventListener("click", event => {
            if (!event.isTrusted) return;
            event.preventDefault();
            event.stopPropagation();
            const password = generatePagePassword();
            // Descriptor hints such as "confirm" also appear on email fields; fill only
            // password inputs.
            const fields = scopeInputs(credentialScope(input)).filter(
                field => field.type === "password" && isNewPasswordInput(field)
            );
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
        control.remove = registerPositionedControl(input, host, positionButton, () => {
            if (generatorControls.get(input) === control) generatorControls.delete(input);
        });
        generatorControls.set(input, control);
    }

    // Brief confirmation under the field; announced politely to screen readers.
    function showToast(input, message) {
        const rect = input.getBoundingClientRect();
        const toast = toastHost(message, Math.max(8, rect.left), rect.bottom + 6);
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3500);
    }

    function dispose() {
        if (disposed) return;
        disposed = true;
        if (pageGeneratorStorage) chrome.storage.onChanged.removeListener(storageChanged);
    }

    return { createGeneratorButton, removeGeneratorButton, dispose };
};
