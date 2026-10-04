const CARD_AUTOCOMPLETE_FIELDS = new Set([
    "cc-name", "cc-given-name", "cc-additional-name", "cc-family-name",
    "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc", "cc-type"
]);
const IDENTITY_AUTOCOMPLETE_FIELDS = new Set([
    "name", "given-name", "additional-name", "family-name", "honorific-prefix",
    "honorific-suffix", "nickname", "email", "tel", "organization",
    "street-address", "address-line1", "address-line2", "address-line3",
    "address-level1", "address-level2", "address-level3", "address-level4",
    "country", "country-name", "postal-code"
]);
const IDENTITY_CONTEXT_FIELDS = new Set([
    "name", "given-name", "additional-name", "family-name", "honorific-prefix",
    "honorific-suffix", "organization", "street-address", "address-line1",
    "address-line2", "address-line3", "address-level1", "address-level2",
    "address-level3", "address-level4", "country", "country-name", "postal-code"
]);

function formScope(input) {
    return input.form || input.closest("[role='form'], dialog, form") || input.parentElement || document;
}

function formControls(scope) {
    const controls = scope instanceof HTMLFormElement
        ? Array.from(scope.elements)
        : Array.from(scope.querySelectorAll("input, select, textarea"));
    return controls.filter(control =>
        control instanceof HTMLInputElement
        || control instanceof HTMLSelectElement
        || control instanceof HTMLTextAreaElement
    );
}

function explicitAutofillField(control, fields) {
    return autocompleteTokens(control).find(token => fields.has(token)) || null;
}

function inferredCardField(control) {
    return PasswordManagerContentFields.inferCard(inputDescriptors(control));
}

function inferredIdentityField(control) {
    return PasswordManagerContentFields.inferIdentity(inputDescriptors(control));
}

function autofillField(control, kind) {
    if (kind === "payment-card") {
        return explicitAutofillField(control, CARD_AUTOCOMPLETE_FIELDS)
            || inferredCardField(control);
    }
    return explicitAutofillField(control, IDENTITY_AUTOCOMPLETE_FIELDS)
        || inferredIdentityField(control);
}

function typedAutofillKind(input) {
    if (!isUsableInput(input)) return null;
    if (autofillField(input, "payment-card")) return "payment-card";

    const identityField = autofillField(input, "identity");
    if (!identityField) return null;
    if (identityField !== "email" && identityField !== "tel") return "identity";

    // Email and phone fields are common on login and search forms. Only attach
    // an identity picker when another address/name field establishes context.
    const controls = formControls(formScope(input));
    return controls.some(control => {
        const field = autofillField(control, "identity");
        return field && IDENTITY_CONTEXT_FIELDS.has(field);
    }) ? "identity" : null;
}

function normalizedFieldName(value) {
    return PasswordManagerContentFields.normalize(value);
}

function customAutofillValue(item, aliases) {
    return PasswordManagerContentFields.customValue(item.custom_fields, aliases);
}

const AUTOFILL_ALIASES = {
    "cc-name": ["cardholder", "cardholder name", "name on card", "cc name"],
    "cc-given-name": ["cardholder first name", "cc given name"],
    "cc-additional-name": ["cardholder middle name", "cc additional name"],
    "cc-family-name": ["cardholder last name", "cc family name"],
    "cc-exp": ["expiration", "expiry", "expiration date", "expiry date", "cc exp"],
    "cc-exp-month": ["expiration month", "expiry month", "exp month", "cc exp month"],
    "cc-exp-year": ["expiration year", "expiry year", "exp year", "cc exp year"],
    "cc-csc": ["cvv", "cvc", "csc", "security code", "card security code"],
    "cc-type": ["card type", "network", "brand"],
    "name": ["name", "full name", "legal name"],
    "given-name": ["first name", "given name"],
    "additional-name": ["middle name", "additional name"],
    "family-name": ["last name", "family name", "surname"],
    "honorific-prefix": ["title", "prefix", "honorific prefix"],
    "honorific-suffix": ["suffix", "honorific suffix"],
    "nickname": ["nickname", "preferred name"],
    "email": ["email", "email address"],
    "tel": ["phone", "telephone", "mobile", "phone number"],
    "organization": ["organization", "company", "business"],
    "street-address": ["street address", "full address", "address"],
    "address-line1": ["address line 1", "address1", "street"],
    "address-line2": ["address line 2", "address2", "apartment", "suite", "unit"],
    "address-line3": ["address line 3", "address3"],
    "address-level1": ["state", "province", "region"],
    "address-level2": ["city", "town"],
    "address-level3": ["district", "county"],
    "address-level4": ["suburb", "neighborhood"],
    "country": ["country code", "country"],
    "country-name": ["country name", "country"],
    "postal-code": ["postal code", "zip", "zip code"]
};

function autofillValue(item, field) {
    if (field === "cc-number") return String(item.primary_secret || "");
    const custom = customAutofillValue(item, AUTOFILL_ALIASES[field] || [field]);
    if (custom) return custom;
    if (field === "cc-name" || field === "email") return accountUsername(item);
    return "";
}

function fillFormControl(control, value) {
    if (!control || control.disabled || control.readOnly || !isElementVisible(control)) return;
    if (control instanceof HTMLSelectElement) {
        const wanted = String(value).trim().toLowerCase();
        const option = Array.from(control.options).find(candidate =>
            candidate.value.trim().toLowerCase() === wanted
            || candidate.text.trim().toLowerCase() === wanted
        );
        control.value = option ? option.value : value;
    } else {
        const prototype = control instanceof HTMLTextAreaElement
            ? HTMLTextAreaElement.prototype
            : HTMLInputElement.prototype;
        const setter = Object.getOwnPropertyDescriptor(prototype, "value")?.set;
        if (setter) setter.call(control, value);
        else control.value = value;
    }
    control.dispatchEvent(new Event("input", { bubbles: true }));
    control.dispatchEvent(new Event("change", { bubbles: true }));
}

function fillTypedItem(anchor, item) {
    const kind = item.kind;
    for (const control of formControls(formScope(anchor))) {
        const field = autofillField(control, kind);
        if (!field) continue;
        const value = autofillValue(item, field);
        if (value) fillFormControl(control, value);
    }
    anchor.focus();
}

function createTypedAutofillButton(input, kind) {
    if (input.dataset.hasTypedAutofill) return;
    input.dataset.hasTypedAutofill = "true";

    const button = document.createElement("button");
    button.type = "button";
    button.className = "my-extension-ui";
    button.innerText = kind === "payment-card" ? "💳" : "👤";
    button.title = kind === "payment-card" ? "Fill payment card" : "Fill identity";
    button.setAttribute("aria-label", button.title);
    Object.assign(button.style, {
        position: "fixed", border: "none", background: "transparent", cursor: "pointer",
        fontSize: "16px", zIndex: "2147483647", padding: "0", margin: "0", display: "none"
    });
    document.body.appendChild(button);

    const menu = document.createElement("div");
    menu.className = "my-extension-ui";
    Object.assign(menu.style, {
        position: "fixed", background: "#fff", color: "#000", border: "1px solid #ccc",
        display: "none", zIndex: "2147483647", minWidth: "220px",
        boxShadow: "0 4px 12px rgba(0,0,0,0.25)", fontFamily: "Arial, sans-serif",
        fontSize: "14px", textAlign: "left"
    });
    document.body.appendChild(menu);

    function positionButton() {
        if (!isElementVisible(input)) {
            button.style.display = "none";
            menu.style.display = "none";
            return;
        }
        const rect = input.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) {
            button.style.display = "none";
            return;
        }
        button.style.display = "";
        button.style.left = rect.right - 24 + "px";
        button.style.top = rect.top + rect.height / 2 - 14 + "px";
    }

    function positionMenu() {
        menu.style.display = "block";
        menu.style.visibility = "hidden";
        const rect = button.getBoundingClientRect();
        const left = Math.min(rect.left, Math.max(4, window.innerWidth - menu.offsetWidth - 4));
        let top = rect.bottom;
        if (top + menu.offsetHeight > window.innerHeight - 4) top = rect.top - menu.offsetHeight;
        menu.style.left = Math.max(4, left) + "px";
        menu.style.top = Math.max(4, top) + "px";
        menu.style.visibility = "";
    }

    function buildMenu(items) {
        menu.innerHTML = "";
        const matching = items.filter(item => item.kind === kind);
        if (matching.length === 0) {
            const empty = document.createElement("div");
            empty.innerText = kind === "payment-card" ? "No payment cards saved" : "No identities saved";
            Object.assign(empty.style, { padding: "8px 12px", color: "#666", fontStyle: "italic" });
            menu.appendChild(empty);
            return;
        }
        for (const saved of matching) {
            const item = document.createElement("button");
            item.type = "button";
            item.innerText = saved.name || accountUsername(saved) || "Unnamed item";
            Object.assign(item.style, {
                display: "block", width: "100%", padding: "8px 12px", border: "none",
                cursor: "pointer", color: "#000", background: "#fff", textAlign: "left"
            });
            item.addEventListener("mouseenter", () => { item.style.background = "#eee"; });
            item.addEventListener("mouseleave", () => { item.style.background = "#fff"; });
            item.addEventListener("click", async event => {
                if (!event.isTrusted) return;
                event.preventDefault();
                event.stopPropagation();
                const selected = await fetchAutofillItem(saved.id);
                if (selected) fillTypedItem(input, selected);
                menu.style.display = "none";
            });
            menu.appendChild(item);
        }
    }

    positionButton();
    const closeOnOutsideClick = event => {
        if (!menu.contains(event.target) && event.target !== button) menu.style.display = "none";
    };
    registerPositionedControl(input, button, menu, positionButton, closeOnOutsideClick);

    button.addEventListener("click", async event => {
        if (!event.isTrusted) return;
        event.preventDefault();
        event.stopPropagation();
        if (menu.style.display === "block") {
            menu.style.display = "none";
            return;
        }
        const items = await fetchAutofillItems();
        buildMenu(items);
        positionMenu();
    });
}

// ===============================
// Attach to username/password inputs
// ===============================
