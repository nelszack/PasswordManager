const test = require("node:test");
const assert = require("node:assert/strict");
const prompt = require("./credential_prompt_state.js");

test("credential lookups distinguish missing sites from native and malformed errors", () => {
    const accounts = [{ id: 7, username: "alice" }];
    for (const [label, response, expected] of [
        ["new site", { success: false, error: "Not found." }, []],
        ["existing site", { success: true, data: accounts }, accounts]
    ]) assert.deepEqual(prompt.accountsFromLookup(response), expected, label);
    for (const [label, response, error] of [
        ["locked vault", { success: false, error: "Vault is locked" }, /locked/],
        ["encoded data", { success: true, data: "not json" }, /Invalid credential response/],
        ["object data", { success: true, data: {} }, /Invalid credential response/]
    ]) assert.throws(() => prompt.accountsFromLookup(response), error, label);
});

test("matching usernames, including literal None, select their own update target", () => {
    for (const [label, username, name] of [["ordinary username", "bob", "Work"], ["literal None", "None", "None account"]]) {
        const data = prompt.describe([
            { id: 7, name: "Other account", username: "alice" },
            { id: 8, name, username, get password() { assert.fail("descriptions must not compare passwords"); } }
        ], username, "https://login.example.com");
        assert.equal(data.hasAccounts, true, label);
        assert.deepEqual(data.updateTarget, { id: 8, name, username }, label);
        assert.equal(data.updateNote, "", label);
        assert.equal(data.suggestedName, name, label);
        assert.equal(data.askForUsername, false, label);
        assert.match(data.message, /already exists/, label);
        assert.equal(data.message.includes("different"), false, label);
        assert.equal(JSON.stringify(data).includes("password"), false, label);
    }
    assert.equal(prompt.accountUsername({ username: null }), "");
});

test("new-site metadata suggests the captured hostname and requests a username", () => {
    const data = prompt.describe([], "", "https://login.example.com:8443");
    assert.equal(data.hasAccounts, false);
    assert.equal(data.site, "https://login.example.com:8443");
    assert.equal(data.suggestedName, "login.example.com");
    assert.equal(data.askForUsername, true);
    assert.equal(data.updateTarget, null);
});

test("completion builds only authorized add and update operations", () => {
    const pending = {
        domain: "https://login.example.com",
        sessionId: "a".repeat(64),
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
            expectedSession: pending.sessionId,
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

test("updating a different account keeps its stored username unless the user edits it", () => {
    const accounts = [{ id: 7, revision: 3, name: "Alice", username: "alice" }];
    const data = prompt.describe(accounts, "bob", "https://login.example.com");
    assert.deepEqual(data.updateTarget, { id: 7, revision: 3, name: "Alice", username: "alice" });
    assert.equal(data.askForUsername, false);
    assert.match(data.message, /No saved account has this username/);
    assert.equal(data.updateNote, "Updating “Alice” changes only its password and keeps the username “alice”.");
    const pending = { domain: "https://login.example.com", sessionId: "a".repeat(64), username: "bob", password: "secret", data };
    // The popup sends the hidden, unedited username field back with every action.
    const update = prompt.operation(pending, { action: "update", name: "Alice", username: "bob" });
    assert.deepEqual(update.fields, {
        domain: pending.domain, expectedSession: pending.sessionId, username: "alice", password: "secret",
        entryId: 7, expectedRevision: 3
    });
    assert.equal(prompt.operation(pending, { action: "update", name: "Alice" }).fields.username, "alice");
    assert.equal(prompt.operation(pending, { action: "update", name: "Alice", username: " carol " }).fields.username, "carol",
        "an explicit edit is applied");
    assert.equal(prompt.operation(pending, { action: "add", name: "Bob", username: "bob" }).fields.username, "bob",
        "a new account keeps the captured username");

    // Password-only steps without a username keep the target's username too.
    const unknown = prompt.describe(accounts, "", "https://login.example.com");
    assert.equal(unknown.updateNote, "");
    const passwordOnly = { ...pending, username: "", data: unknown };
    assert.equal(prompt.operation(passwordOnly, { action: "update", name: "Alice", username: "" }).fields.username, "alice");
    assert.equal(prompt.operation(passwordOnly, { action: "update", name: "Alice", username: "alice2" }).fields.username, "alice2");
});
