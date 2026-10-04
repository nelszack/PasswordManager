(function (root, factory) {
    const api = factory();
    root.PasswordManagerContentDetection = api;
    if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    "use strict";

    const USERNAME_HINT_RE = /user(name)?|login|e-?mail|account|sign-?in|auth/i;
    const SEARCH_HINT_RE = /search|query|lookup|find/i;
    const TOTP_HINT_RE = /\b(otp|totp|2fa|mfa)\b|one[-_ ]?time|verification[-_ ]?(code|token)|security[-_ ]?code|authenticator[-_ ]?code/i;
    const USERNAME_INPUT_TYPES = new Set(["text", "email", "tel"]);

    function inputDescriptors(input) {
        return [
            input.name, input.id, input.className, input.autocomplete,
            input.getAttribute("type"), input.getAttribute("placeholder"),
            input.getAttribute("aria-label"), input.getAttribute("role")
        ].filter(Boolean).map(String);
    }

    function autocompleteTokens(input) {
        return (input.autocomplete || "").toLowerCase().split(/\s+/).filter(Boolean);
    }

    function isElementVisible(element) {
        if (!element || !element.isConnected) return false;
        let node = element;
        while (node && node.nodeType === 1) {
            const style = getComputedStyle(node);
            if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") return false;
            node = node.parentElement;
        }
        return true;
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
        return input.type === "search" || input.getAttribute("role") === "searchbox"
            || inputDescriptors(input).some(value => SEARCH_HINT_RE.test(value));
    }

    function isNewPasswordInput(input) {
        return autocompleteTokens(input).includes("new-password")
            || inputDescriptors(input).some(value => /confirm|repeat|retype|new[-_ ]?pass|create[-_ ]?pass/i.test(value));
    }

    function isLoginPasswordInput(input) {
        return isUsableInput(input) && input.type === "password" && !isNewPasswordInput(input);
    }

    function usernameCandidates(fields) {
        return fields.filter(field => isUsableInput(field)
            && USERNAME_INPUT_TYPES.has(field.type) && !hasSearchHint(field));
    }

    function credentialScope(input) {
        if (input.form) return input.form;
        const explicitScope = input.closest("[role='form'], dialog");
        if (explicitScope) return explicitScope;
        let candidate = input.parentElement;
        while (candidate && candidate !== document.body) {
            const fields = Array.from(candidate.querySelectorAll("input")).filter(isUsableInput);
            if (fields.some(field => field.type === "password")
                && fields.some(field => USERNAME_INPUT_TYPES.has(field.type) && !hasSearchHint(field))) {
                return candidate;
            }
            candidate = candidate.parentElement;
        }
        return input.parentElement || document;
    }

    function chooseUsernameField(fields, anchor) {
        const candidates = usernameCandidates(fields);
        const preceding = anchor ? candidates.filter(field => fields.indexOf(field) < fields.indexOf(anchor)) : candidates;
        const pool = preceding.length ? preceding : candidates;
        return pool.find(field => autocompleteTokens(field).some(token => token === "username" || token === "email"))
            || pool.find(hasUsernameHint) || pool.at(-1) || null;
    }

    function choosePasswordField(fields, anchor) {
        const candidates = fields.filter(isLoginPasswordInput);
        return candidates.find(field => autocompleteTokens(field).includes("current-password"))
            || (anchor && candidates.find(field => fields.indexOf(field) > fields.indexOf(anchor)))
            || candidates[0] || null;
    }

    function credentialFields(input) {
        const scope = credentialScope(input);
        const fields = scopeInputs(scope);
        return {
            scope,
            usernameField: USERNAME_INPUT_TYPES.has(input.type) ? input : chooseUsernameField(fields, input),
            passwordField: isLoginPasswordInput(input) ? input : choosePasswordField(fields, input)
        };
    }

    function isTotpInput(input) {
        if (!isUsableInput(input)) return false;
        if (autocompleteTokens(input).includes("one-time-code")) return true;
        return ["text", "tel", "number"].includes(input.type)
            && inputDescriptors(input).some(value => TOTP_HINT_RE.test(value));
    }

    function isUsernameBeforePassword(input, formUsernames) {
        if (!input.form) return false;
        if (formUsernames?.has(input.form)) return formUsernames.get(input.form) === input;
        const fields = scopeInputs(input.form);
        const passwordIndex = fields.findIndex(isLoginPasswordInput);
        const username = passwordIndex < 0 ? null : fields.slice(0, passwordIndex)
            .filter(field => isUsableInput(field) && USERNAME_INPUT_TYPES.has(field.type) && !hasSearchHint(field))
            .at(-1);
        formUsernames?.set(input.form, username);
        return username === input;
    }

    function isCredentialInput(input, formUsernames) {
        if (!isUsableInput(input)) return false;
        if (input.type === "password") return !isNewPasswordInput(input);
        if (!USERNAME_INPUT_TYPES.has(input.type) || hasSearchHint(input)) return false;
        return hasUsernameHint(input) || isUsernameBeforePassword(input, formUsernames);
    }

    return {
        USERNAME_INPUT_TYPES, autocompleteTokens, credentialFields, credentialScope,
        hasSearchHint, hasUsernameHint, inputDescriptors, isCredentialInput,
        isElementVisible, isLoginPasswordInput, isNewPasswordInput, isTotpInput,
        isUsableInput, scopeInputs, usernameCandidates
    };
});
