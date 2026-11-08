// Representative typed DTOs shared by transport tests; browser tests use the real
// native host or the isolated stateful host fixture.
const summary = (fields = {}) => ({ id: 1, revision: 1, name: "Personal", username: "alice", kind: "login",
    urls: ["https://shop.example"], has_totp: true, has_duo: false, ...fields });
function baseNativeFields(action) {
    switch (action) {
        case "duoRequests": case "getTotp": case "getAutofillItem": return { entryId: 1 };
        case "duoRespond": return { entryId: 1, requestId: "test-request", fingerprint: "a".repeat(128), approve: true };
        case "getLoginItems": case "getDuoItems": return { domain: "https://shop.example" };
        case "getLoginItem": return { domain: "https://shop.example", entryId: 1 };
        case "saveCredentials": return { domain: "https://shop.example", username: "alice", password: "synthetic", name: "Example" };
        case "updateCredentials": return { domain: "https://shop.example", username: "alice", password: "synthetic", entryId: 1, expectedRevision: 1 };
        default: return {};
    }
}
const sessionId = "a".repeat(64);
function nativeFields(action) {
    const fields = baseNativeFields(action);
    if (["duoRequests", "duoRespond", "getLoginItem", "getAutofillItem", "getTotp", "saveCredentials", "updateCredentials"].includes(action)) fields.expectedSession = sessionId;
    if (["getLoginItem", "getAutofillItem", "getTotp"].includes(action)) fields.expectedRevision = 1;
    if (action === "getTotp") fields.domain = "https://shop.example";
    return fields;
}
function nativeData(action) {
    switch (action) {
        case "status": return { locked: false, version: "0.1.0", warning: null };
        case "duoRequests": return [];
        case "getLoginItems": case "getDuoItems": return [summary()];
        case "getAutofillItems": return [summary({ id: 2, name: "Visa", kind: "payment-card" })];
        case "getLoginItem": return { id: 1, revision: 1, name: "Personal", username: "alice", password: "synthetic-secret", has_totp: true };
        case "getAutofillItem": return { id: 2, revision: 1, name: "Visa", kind: "payment-card", username: null, primary_secret: "synthetic-card", custom_fields: [] };
        case "getTotp": return { mode: "totp", code: "123456", expires_in: 24, counter: null };
        default: return "Saved";
    }
}
module.exports = { summary, nativeFields, nativeData, sessionId };
