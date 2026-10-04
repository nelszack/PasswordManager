const test = require("node:test");
const assert = require("node:assert/strict");
const prompt = require("./credential_prompt_state.js");

test("credential lookups distinguish missing sites from native and malformed errors", () => {
    // a missing site is treated as an empty credential lookup
    {
        assert.deepEqual(prompt.accountsFromLookup({
            success: false,
            error: "Not found."
        }), []);
        assert.deepEqual(prompt.accountsFromLookup({
            success: true,
            data: '[{"id":7,"username":"alice"}]'
        }), [{ id: 7, username: "alice" }]);
    }
    // credential lookup still reports native and malformed response errors
    {
        assert.throws(() => prompt.accountsFromLookup({
            success: false,
            error: "Vault is locked"
        }), /locked/);
        assert.throws(() => prompt.accountsFromLookup({
            success: true,
            data: "not json"
        }), /Invalid credential response/);
        assert.throws(() => prompt.accountsFromLookup({
            success: true,
            data: "{}"
        }), /Invalid credential response/);
    }
});


test("credential prompt metadata selects a matching username for updates", () => {
    const data = prompt.describe([
        { id: 7, name: "Personal", username: "alice" },
        { id: 8, name: "Work", username: "bob" }
    ], "bob", "https://login.example.com");

    assert.equal(data.hasAccounts, true);
    assert.deepEqual(data.updateTarget, { id: 8, name: "Work" });
    assert.equal(data.suggestedName, "Work");
    assert.equal(data.askForUsername, false);
});

test("new-site metadata suggests the captured hostname and requests a username", () => {
    const data = prompt.describe([], "", "https://login.example.com:8443");
    assert.equal(data.hasAccounts, false);
    assert.equal(data.site, "https://login.example.com:8443");
    assert.equal(data.suggestedName, "login.example.com");
    assert.equal(data.askForUsername, true);
    assert.equal(data.updateTarget, null);
});

test("prompt descriptions use usernames and never make password comparisons", () => {
    const accounts = [{ id: 1, name: "Personal", username: "alice" }];
    const data = prompt.describe(accounts, "alice", "https://example.com");
    assert.equal(data.hasAccounts, true);
    assert.match(data.message, /already exists/);
    assert.equal(data.message.includes("different"), false);
    assert.equal(JSON.stringify(data).includes("password"), false);
});

test("completion builds only authorized add and update operations", () => {
    const pending = {
        domain: "https://login.example.com",
        username: "alice",
        password: "secret",
        data: { updateTarget: { id: 7, name: "Personal" } }
    };
    assert.deepEqual(prompt.operation(pending, {
        action: "add", name: " New account ", username: " alice@example.com "
    }), {
        action: "add",
        fields: {
            domain: pending.domain,
            username: "alice@example.com",
            password: "secret",
            name: "New account"
        }
    });
    assert.equal(prompt.operation(pending, { action: "cancel" }).action, "cancel");
    assert.equal(prompt.operation(pending, { action: "update", name: "Personal" }).fields.entryId, 7);
    assert.throws(() => prompt.operation(pending, { action: "delete", name: "Personal" }));
    assert.throws(() => prompt.operation({ ...pending, data: {} }, {
        action: "update", name: "Personal"
    }));
});

test("completion rejects empty names without exposing secrets in popup metadata", () => {
    const pending = {
        domain: "https://example.com",
        username: "alice",
        password: "must-not-leak",
        data: prompt.describe([], "alice", "https://example.com")
    };
    assert.equal(JSON.stringify(pending.data).includes(pending.password), false);
    assert.throws(() => prompt.operation(pending, { action: "add", name: "  " }), /name/);
});
