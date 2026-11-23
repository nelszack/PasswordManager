(function (root, factory) {
    const api = factory();
    if (typeof module === "object" && module.exports) module.exports = api;
    else root.PasswordManagerContentDetection = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    "use strict";

    const USERNAME_HINT_RE = /user(name)?|login|e-?mail|account|sign-?in|auth|identif/i;
    const SEARCH_HINT_RE = /search|query|lookup|find/i;
    const TOTP_HINT_RE =
        /\b(otp|totp|2fa|mfa)\b|one[-_ ]?time|verification[-_ ]?(code|token)|security[-_ ]?code|authenticator[-_ ]?code/i;
    // Only explicit card-code wording: descriptors include CSS classes such as "card-input".
    const CARD_CODE_HINT_RE = /\b(cvv2?|cvc2?|csc)\b|card[-_ ]?(security|verification)/i;
    const USERNAME_INPUT_TYPES = new Set(["text", "email", "tel"]);

    function inputDescriptors(input) {
        return [
            input.name,
            input.id,
            input.className,
            input.autocomplete,
            input.getAttribute("type"),
            input.getAttribute("placeholder"),
            input.getAttribute("aria-label"),
            input.getAttribute("role"),
            ...Array.from(input.labels || [], label => label.textContent),
        ]
            .filter(Boolean)
            .map(String);
    }

    function autocompleteTokens(input) {
        return (input.autocomplete || "").toLowerCase().split(/\s+/).filter(Boolean);
    }

    let scanVisibility = null;
    // Cache only within one synchronous read phase; page changes never reuse it.
    function withVisibilityCache(action) {
        const previous = scanVisibility;
        scanVisibility = new WeakMap();
        try {
            return action();
        } finally {
            scanVisibility = previous;
        }
    }
    function isElementVisible(element) {
        if (!element || !element.isConnected) return false;
        const visited = [];
        let visible = true;
        for (let node = element; node && node.nodeType === 1; node = node.parentElement || node.getRootNode?.().host) {
            if (scanVisibility?.has(node)) {
                visible = scanVisibility.get(node);
                break;
            }
            visited.push(node);
            const style = getComputedStyle(node);
            // Material-style fields (Vuetify, for one) keep the input itself
            // transparent until focused so a floating label shows through; only
            // a transparent container hides a field.
            const transparent = style.opacity === "0" && !(node === element && node instanceof HTMLInputElement);
            if (style.display === "none" || style.visibility === "hidden" || transparent) {
                visible = false;
                break;
            }
        }
        for (const node of visited) scanVisibility?.set(node, visible);
        return visible;
    }

    function isUsableInput(input) {
        return input instanceof HTMLInputElement && !input.disabled && !input.readOnly && isElementVisible(input);
    }

    function scopeInputs(scope) {
        if (scope instanceof HTMLFormElement) {
            return Array.from(scope.elements).filter(element => element instanceof HTMLInputElement);
        }
        return Array.from(scope.querySelectorAll("input"));
    }

    function hasUsernameHint(input) {
        return inputDescriptors(input).some(value => USERNAME_HINT_RE.test(value));
    }

    function hasSearchHint(input) {
        return (
            input.type === "search" ||
            input.getAttribute("role") === "searchbox" ||
            inputDescriptors(input).some(value => SEARCH_HINT_RE.test(value))
        );
    }

    function isNewPasswordInput(input) {
        return (
            autocompleteTokens(input).includes("new-password") ||
            inputDescriptors(input).some(value => /confirm|repeat|retype|new[-_ ]?pass|create[-_ ]?pass/i.test(value))
        );
    }

    function isLoginPasswordInput(input) {
        return isUsableInput(input) && input.type === "password" && !isNewPasswordInput(input);
    }

    function usernameCandidates(fields) {
        return fields.filter(field => {
            if (
                !isUsableInput(field) ||
                !USERNAME_INPUT_TYPES.has(field.type) ||
                hasSearchHint(field) ||
                isTotpInput(field)
            )
                return false;
            const tokens = autocompleteTokens(field).filter(
                token =>
                    !token.startsWith("section-") && !["shipping", "billing", "on", "off", "webauthn"].includes(token)
            );
            return !tokens.length || tokens.some(token => ["username", "email", "tel"].includes(token));
        });
    }

    function credentialScope(input) {
        if (input.form) return input.form;
        const explicitScope = input.closest("[role='form'], dialog");
        if (explicitScope) return explicitScope;
        let candidate = input.parentElement;
        while (candidate && candidate !== document.body) {
            // Check cheap type tests first and stop as soon as both roles are
            // present; visibility checks read computed styles up the tree.
            let password = false;
            let username = false;
            for (const field of candidate.querySelectorAll("input")) {
                if (!password && field.type === "password") password = isUsableInput(field);
                else if (!username && USERNAME_INPUT_TYPES.has(field.type))
                    username = !hasSearchHint(field) && isUsableInput(field);
                if (password && username) return candidate;
            }
            candidate = candidate.parentElement;
        }
        return input.parentElement || document;
    }

    function chooseUsernameField(fields, anchor) {
        const candidates = usernameCandidates(fields);
        const preceding = anchor
            ? candidates.filter(field => fields.indexOf(field) < fields.indexOf(anchor))
            : candidates;
        const pool = preceding.length ? preceding.toReversed() : candidates;
        return (
            pool.find(field => autocompleteTokens(field).some(token => token === "username" || token === "email")) ||
            pool.find(hasUsernameHint) ||
            (preceding.length ? pool[0] : pool.at(-1)) ||
            null
        );
    }

    function choosePasswordField(fields, anchor) {
        const candidates = fields.filter(isLoginPasswordInput);
        return (
            (anchor && candidates.find(field => fields.indexOf(field) > fields.indexOf(anchor))) ||
            candidates.find(field => autocompleteTokens(field).includes("current-password")) ||
            candidates[0] ||
            null
        );
    }

    function credentialFields(input, scope = credentialScope(input)) {
        const fields = scopeInputs(scope);
        return {
            scope,
            usernameField: usernameCandidates(fields).includes(input) ? input : chooseUsernameField(fields, input),
            passwordField:
                fields.includes(input) && isLoginPasswordInput(input) ? input : choosePasswordField(fields, input),
        };
    }

    function isTotpInput(input) {
        if (!isUsableInput(input)) return false;
        const tokens = autocompleteTokens(input);
        if (tokens.includes("one-time-code")) return true;
        // A card's "security code" (CVC) is not a sign-in code.
        if (tokens.some(token => token.startsWith("cc-"))) return false;
        const descriptors = inputDescriptors(input);
        if (descriptors.some(value => CARD_CODE_HINT_RE.test(value))) return false;
        return ["text", "tel", "number"].includes(input.type) && descriptors.some(value => TOTP_HINT_RE.test(value));
    }

    function isUsernameBeforePassword(input, formUsernames) {
        if (!input.form) return false;
        if (formUsernames?.has(input.form)) return formUsernames.get(input.form) === input;
        const fields = scopeInputs(input.form);
        const passwordIndex = fields.findIndex(isLoginPasswordInput);
        const username = passwordIndex < 0 ? null : usernameCandidates(fields.slice(0, passwordIndex)).at(-1);
        formUsernames?.set(input.form, username);
        return username === input;
    }

    function isCredentialInput(input, formUsernames) {
        if (!isUsableInput(input)) return false;
        if (input.type === "password") return !isNewPasswordInput(input);
        if (!usernameCandidates([input]).length) return false;
        return hasUsernameHint(input) || isUsernameBeforePassword(input, formUsernames);
    }

    // Buttons that only reveal or mask a password are not login steps.
    const VISIBILITY_TOGGLE_RE = /show|hide|reveal|unmask|toggle|visib|(?<![a-z])eye|eye(?![a-z])/i;
    function isVisibilityToggle(control) {
        if (!control?.getAttribute) return false;
        if (control.hasAttribute?.("aria-pressed")) return true;
        const text = String(control.textContent || "").trim();
        return [
            control.id,
            control.getAttribute("class"),
            control.getAttribute("name"),
            control.getAttribute("title"),
            control.getAttribute("aria-label"),
            control.getAttribute("data-testid"),
            control instanceof HTMLInputElement ? control.value : "",
            text.length <= 40 ? text : "",
        ].some(value => value && VISIBILITY_TOGGLE_RE.test(String(value)));
    }

    // Hosts of the extension's in-page controls. A registry rather than a class
    // name or tag, so pages cannot make their own elements look like ours.
    const extensionUi = new WeakSet();
    function markExtensionUi(element) {
        extensionUi.add(element);
        return element;
    }
    function isExtensionUi(node) {
        return Boolean(node) && extensionUi.has(node);
    }

    return {
        USERNAME_INPUT_TYPES,
        isExtensionUi,
        isVisibilityToggle,
        markExtensionUi,
        autocompleteTokens,
        credentialFields,
        credentialScope,
        hasSearchHint,
        hasUsernameHint,
        inputDescriptors,
        isCredentialInput,
        isElementVisible,
        isLoginPasswordInput,
        isNewPasswordInput,
        isTotpInput,
        isUsableInput,
        scopeInputs,
        usernameCandidates,
        withVisibilityCache,
    };
});
