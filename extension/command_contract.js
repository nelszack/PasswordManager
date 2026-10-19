// Generated from Rust native-operation policy; do not edit by hand.
(function (root, factory) {
    const api = factory();
    root.PasswordManagerCommandContract = api;
    if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    "use strict";
    const protocolVersion = 1;
    const operations = Object.freeze({
  "getAutofillItem": {
    "mutates": false,
    "lane": "work",
    "timeoutMs": 15000,
    "allowedSenders": [
      "background"
    ],
    "requiredFields": [
      "entryId"
    ],
    "optionalFields": [],
    "resultShape": "autofill"
  },
  "getAutofillItems": {
    "mutates": false,
    "lane": "work",
    "timeoutMs": 15000,
    "allowedSenders": [
      "background"
    ],
    "requiredFields": [],
    "optionalFields": [],
    "resultShape": "summaryArray"
  },
  "getDuoItems": {
    "mutates": false,
    "lane": "duo",
    "timeoutMs": 15000,
    "allowedSenders": [
      "background"
    ],
    "requiredFields": [
      "domain"
    ],
    "optionalFields": [],
    "resultShape": "summaryArray"
  },
  "getLoginItem": {
    "mutates": false,
    "lane": "work",
    "timeoutMs": 15000,
    "allowedSenders": [
      "background"
    ],
    "requiredFields": [
      "domain",
      "entryId"
    ],
    "optionalFields": [],
    "resultShape": "login"
  },
  "getLoginItems": {
    "mutates": false,
    "lane": "work",
    "timeoutMs": 15000,
    "allowedSenders": [
      "background"
    ],
    "requiredFields": [
      "domain"
    ],
    "optionalFields": [],
    "resultShape": "summaryArray"
  },
  "getTotp": {
    "mutates": true,
    "lane": "work",
    "timeoutMs": 15000,
    "allowedSenders": [
      "background"
    ],
    "requiredFields": [
      "entryId"
    ],
    "optionalFields": [],
    "resultShape": "authenticator"
  },
  "lock": {
    "mutates": true,
    "lane": "control",
    "timeoutMs": 15000,
    "allowedSenders": [
      "manager",
      "popup",
      "background"
    ],
    "requiredFields": [],
    "optionalFields": [],
    "resultShape": "message"
  },
  "managerAdd": {
    "mutates": true,
    "lane": "work",
    "timeoutMs": 15000,
    "allowedSenders": [
      "manager",
      "background"
    ],
    "requiredFields": [
      "item"
    ],
    "optionalFields": [],
    "resultShape": "message"
  },
  "managerCopy": {
    "mutates": true,
    "lane": "work",
    "timeoutMs": 15000,
    "allowedSenders": [
      "manager",
      "background"
    ],
    "requiredFields": [
      "entryId"
    ],
    "optionalFields": [],
    "resultShape": "message"
  },
  "managerDelete": {
    "mutates": true,
    "lane": "work",
    "timeoutMs": 15000,
    "allowedSenders": [
      "manager",
      "background"
    ],
    "requiredFields": [
      "entryId",
      "expectedRevision"
    ],
    "optionalFields": [],
    "resultShape": "message"
  },
  "managerDuoRequests": {
    "mutates": false,
    "lane": "duo",
    "timeoutMs": 65000,
    "allowedSenders": [
      "manager",
      "background"
    ],
    "requiredFields": [
      "entryId"
    ],
    "optionalFields": [],
    "resultShape": "duoArray"
  },
  "managerDuoRespond": {
    "mutates": true,
    "lane": "duo",
    "timeoutMs": 65000,
    "allowedSenders": [
      "manager",
      "background"
    ],
    "requiredFields": [
      "entryId",
      "requestId",
      "fingerprint",
      "approve"
    ],
    "optionalFields": [
      "verificationCode"
    ],
    "resultShape": "message"
  },
  "managerItem": {
    "mutates": false,
    "lane": "work",
    "timeoutMs": 15000,
    "allowedSenders": [
      "manager",
      "background"
    ],
    "requiredFields": [
      "entryId"
    ],
    "optionalFields": [
      "reveal"
    ],
    "resultShape": "item"
  },
  "managerList": {
    "mutates": false,
    "lane": "work",
    "timeoutMs": 15000,
    "allowedSenders": [
      "manager",
      "background"
    ],
    "requiredFields": [],
    "optionalFields": [
      "query"
    ],
    "resultShape": "itemPage"
  },
  "managerUnlock": {
    "mutates": true,
    "lane": "work",
    "timeoutMs": 15000,
    "allowedSenders": [
      "manager",
      "background"
    ],
    "requiredFields": [],
    "optionalFields": [
      "vaultFile",
      "password",
      "keyPath"
    ],
    "resultShape": "message"
  },
  "managerUpdate": {
    "mutates": true,
    "lane": "work",
    "timeoutMs": 15000,
    "allowedSenders": [
      "manager",
      "background"
    ],
    "requiredFields": [
      "entryId",
      "expectedRevision",
      "item"
    ],
    "optionalFields": [],
    "resultShape": "message"
  },
  "managerVaults": {
    "mutates": false,
    "lane": "work",
    "timeoutMs": 15000,
    "allowedSenders": [
      "manager",
      "background"
    ],
    "requiredFields": [],
    "optionalFields": [],
    "resultShape": "vaultArray"
  },
  "operationStatus": {
    "mutates": false,
    "lane": "control",
    "timeoutMs": 15000,
    "allowedSenders": [
      "manager",
      "prompt",
      "background"
    ],
    "requiredFields": [
      "operationId"
    ],
    "optionalFields": [],
    "resultShape": "receipt"
  },
  "saveCredentials": {
    "mutates": true,
    "lane": "work",
    "timeoutMs": 15000,
    "allowedSenders": [
      "background"
    ],
    "requiredFields": [
      "domain",
      "password",
      "name"
    ],
    "optionalFields": [
      "username"
    ],
    "resultShape": "message"
  },
  "status": {
    "mutates": false,
    "lane": "control",
    "timeoutMs": 15000,
    "allowedSenders": [
      "background"
    ],
    "requiredFields": [],
    "optionalFields": [],
    "resultShape": "status"
  },
  "updateCredentials": {
    "mutates": true,
    "lane": "work",
    "timeoutMs": 15000,
    "allowedSenders": [
      "background"
    ],
    "requiredFields": [
      "domain",
      "entryId",
      "password",
      "expectedRevision"
    ],
    "optionalFields": [
      "username"
    ],
    "resultShape": "message"
  }
});
    const kinds = new Set(["login", "secure-note", "payment-card", "identity", "wifi", "software-license", "ssh-key", "api-secret"]);
    const outcomeStates = new Set(["pending", "committed", "committed_durability_unknown", "failed", "unknown"]);
    const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
    const integer = value => Number.isSafeInteger(value) && value >= 0;
    const positive = value => integer(value) && value > 0;
    const text = value => typeof value === "string";
    const nullableText = value => value === null || text(value);
    const unsigned64 = value => text(value) && /^(0|[1-9]\d{0,19})$/.test(value) && BigInt(value) <= 18446744073709551615n;
    const identifier = value => text(value) && /^[a-zA-Z0-9_-]{1,128}$/.test(value);
    function bounded(value, limit, singleLine = false) {
        return text(value) && new TextEncoder().encode(value).length <= limit && (!singleLine || !/[\0\r\n]/.test(value));
    }
    function fail(message) { throw new Error(message); }
    function validField(field) {
        return object(field) && bounded(field.name, 4096) && field.name.trim().length > 0
            && bounded(field.value, 65536) && typeof field.secret === "boolean"
            && Object.keys(field).every(key => ["name", "value", "secret"].includes(key));
    }
    function validManagementInput(item) {
        if (!object(item) || !bounded(item.name, 4096, true) || !item.name.trim()) return false;
        const allowed = ["name", "username", "password", "kind", "urls", "notes", "fields", "removeFields", "removeUrls"];
        if (Object.keys(item).some(key => !allowed.includes(key))) return false;
        if (item.username != null && !bounded(item.username, 4096, true)) return false;
        if (item.password != null && !bounded(item.password, 65536)) return false;
        if (item.notes != null && !bounded(item.notes, 65536)) return false;
        if (item.kind != null && !kinds.has(item.kind)) return false;
        for (const key of ["urls", "removeUrls"]) {
            if (item[key] != null && (!Array.isArray(item[key]) || item[key].length > 100 || !item[key].every(url => bounded(url, 2048, true)))) return false;
        }
        if (item.removeFields != null && (!Array.isArray(item.removeFields) || item.removeFields.length > 100 || !item.removeFields.every(name => bounded(name, 4096) && name.length > 0))) return false;
        if (item.fields != null) {
            if (!Array.isArray(item.fields) || item.fields.length > 100 || !item.fields.every(validField)) return false;
            const names = item.fields.map(field => field.name.toLowerCase());
            if (new Set(names).size !== names.length) return false;
        }
        return true;
    }
    function validateRequest(action, fields = {}) {
        const policy = operations[action];
        if (!policy || !object(fields)) fail("Unsupported native operation");
        const allowed = new Set([...policy.requiredFields, ...policy.optionalFields, ...(policy.mutates ? ["operationId"] : [])]);
        for (const [key, value] of Object.entries(fields)) {
            if (value === undefined) continue;
            if (!allowed.has(key)) fail("Unexpected native request field");
            let valid;
            switch (key) {
                case "operationId": valid = identifier(value); break;
                case "entryId": valid = positive(value); break;
                case "expectedRevision": valid = integer(value); break;
                case "item": valid = validManagementInput(value); break;
                case "reveal": case "approve": valid = typeof value === "boolean"; break;
                case "domain": valid = bounded(value, 2048, true) && value.length > 0; break;
                case "password": valid = bounded(value, 65536); break;
                case "username": case "name": valid = bounded(value, 4096, true); break;
                case "query": valid = bounded(value, 4096, true); break;
                case "vaultFile": valid = bounded(value, 255, true) && /^[a-zA-Z0-9._-]+$/.test(value); break;
                case "keyPath": valid = bounded(value, 4096, true) && value.length > 0; break;
                case "requestId": valid = bounded(value, 256, true) && /^[a-zA-Z0-9_-]+$/.test(value); break;
                case "fingerprint": valid = text(value) && /^[a-fA-F0-9]{128}$/.test(value); break;
                case "verificationCode": valid = text(value) && /^\d{0,6}$/.test(value); break;
                default: valid = false;
            }
            if (!valid) fail("Invalid native request field");
        }
        for (const key of policy.requiredFields) if (fields[key] === undefined || fields[key] === null) fail("Missing native request field");
        if (policy.mutates && !identifier(fields.operationId)) fail("Mutation requires an operation ID");
        if (action === "managerUnlock" && !fields.password && !fields.keyPath) fail("Choose a master password or key path");
        if (action === "managerUnlock" && fields.password && fields.keyPath) fail("Choose one unlock credential");
        if (action === "managerDuoRespond" && !fields.approve && fields.verificationCode) fail("Denial cannot include a verification code");
        return fields;
    }
    function summary(item) {
        return object(item) && positive(item.id) && integer(item.revision) && text(item.name)
            && nullableText(item.username) && kinds.has(item.kind) && Array.isArray(item.urls) && item.urls.every(text)
            && typeof item.has_totp === "boolean" && typeof item.has_duo === "boolean";
    }
    function receipt(value) {
        return object(value) && identifier(value.operationId) && outcomeStates.has(value.state)
            && (value.revision === null || integer(value.revision));
    }
    function detail(item) {
        return summary(item) && nullableText(item.notes) && nullableText(item.password)
            && typeof item.has_secret === "boolean" && text(item.created) && text(item.modified)
            && Array.isArray(item.fields) && item.fields.every(field => object(field) && text(field.name)
                && typeof field.secret === "boolean" && nullableText(field.value));
    }
    function authenticator(value) {
        return object(value) && text(value.code) && /^\d{6,8}$/.test(value.code)
            && (value.mode === "totp" && positive(value.expires_in) && value.counter === null
                || value.mode === "hotp" && value.expires_in === null && unsigned64(value.counter));
    }
    function duoRequest(value) {
        return object(value) && text(value.id) && text(value.application) && text(value.username)
            && text(value.location) && text(value.summary) && integer(value.expires_at)
            && (value.code_digits === null || positive(value.code_digits)) && nullableText(value.unsupported)
            && text(value.fingerprint) && /^[a-fA-F0-9]{128}$/.test(value.fingerprint);
    }
    function validateResult(action, data) {
        const policy = operations[action];
        if (!policy) fail("Unsupported native operation");
        // A committed result may have been discarded on lock; the receipt remains.
        if (policy.mutates && receipt(data)) return data;
        let valid = false;
        switch (policy.resultShape) {
            case "message": valid = text(data); break;
            case "status": valid = object(data) && typeof data.locked === "boolean" && text(data.version) && nullableText(data.warning); break;
            case "vaultArray": valid = Array.isArray(data) && data.every(text); break;
            case "summaryArray": valid = Array.isArray(data) && data.every(summary); break;
            case "itemPage": valid = object(data) && Array.isArray(data.items) && data.items.every(summary) && integer(data.total) && data.total >= data.items.length; break;
            case "item": valid = detail(data); break;
            case "login": valid = object(data) && positive(data.id) && integer(data.revision) && text(data.name) && nullableText(data.username) && text(data.password) && typeof data.has_totp === "boolean"; break;
            case "autofill": valid = object(data) && positive(data.id) && integer(data.revision) && text(data.name) && kinds.has(data.kind) && nullableText(data.username) && text(data.primary_secret) && Array.isArray(data.custom_fields) && data.custom_fields.every(validField); break;
            case "authenticator": valid = authenticator(data); break;
            case "duoArray": valid = Array.isArray(data) && data.every(duoRequest); break;
            case "receipt": valid = receipt(data); break;
        }
        if (!valid) fail("Invalid native operation result");
        return data;
    }
    return { protocolVersion, operations, validateRequest, validateResult };
});
