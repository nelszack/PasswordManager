var PasswordManagerContentFields = (() => {
    function inferCard(descriptors) {
        const description = descriptors.filter(Boolean).join(" ").toLowerCase();
        if (/cvc|cvv|card.?security|security.?code/.test(description)) return "cc-csc";
        if (/expir.*month|exp.?month|cc.?month/.test(description)) return "cc-exp-month";
        if (/expir.*year|exp.?year|cc.?year/.test(description)) return "cc-exp-year";
        if (/expir|card.?exp|cc.?exp/.test(description)) return "cc-exp";
        if (/cardholder|name.?on.?card|cc.?name/.test(description)) return "cc-name";
        if (/card.?number|cc.?number|credit.?card/.test(description)) return "cc-number";
        return null;
    }

    function inferIdentity(descriptors) {
        const description = descriptors.filter(Boolean).join(" ").toLowerCase();
        if (/postal|zip/.test(description)) return "postal-code";
        if (/address.?line.?3/.test(description)) return "address-line3";
        if (/address.?line.?2|apartment|suite|unit/.test(description)) return "address-line2";
        if (/street|address.?line.?1/.test(description)) return "address-line1";
        if (/city|town/.test(description)) return "address-level2";
        if (/state|province|region|county/.test(description)) return "address-level1";
        if (/country/.test(description)) return "country";
        if (/first|given/.test(description) && /name/.test(description)) return "given-name";
        if (/last|family|surname/.test(description)) return "family-name";
        if (/full.?name|contact.?name/.test(description)) return "name";
        if (/company|organization/.test(description)) return "organization";
        if (/phone|mobile|telephone/.test(description)) return "tel";
        if (/e-?mail/.test(description)) return "email";
        return null;
    }

    function normalize(value) {
        return String(value || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    }

    function customValue(fields, aliases) {
        const accepted = new Set(aliases.map(normalize));
        const field = (Array.isArray(fields) ? fields : []).find(candidate =>
            candidate && accepted.has(normalize(candidate.name))
        );
        return field ? String(field.value ?? "") : "";
    }

    return { inferCard, inferIdentity, normalize, customValue };
})();

if (typeof module !== "undefined") module.exports = PasswordManagerContentFields;
