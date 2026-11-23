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
    // A reviewed, corrected password replaces the captured one; invalid ones are refused.
    assert.equal(prompt.operation(pending, { action: "add", name: "A", password: "fixed" }).fields.password, "fixed");
    for (const password of ["", 5, "a\nb", "x".repeat(64 * 1024 + 1)]) {
        assert.throws(() => prompt.operation(pending, { action: "add", name: "A", password }), /password/);
    }
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
    // A change-password form shows no username: the site's only login is the likely target.
    assert.equal(unknown.preferUpdate, true);
    assert.match(unknown.message, /^Update the saved password for “Alice”/);
    const twoAccounts = prompt.describe([...accounts, { id: 9, name: "Other", username: "o" }], "", "https://login.example.com");
    assert.equal(twoAccounts.preferUpdate, false);
    assert.match(twoAccounts.message, /No saved account has this username/);
    assert.equal(prompt.describe(accounts, "bob", "https://login.example.com").preferUpdate, false);
    const passwordOnly = { ...pending, username: "", data: unknown };
    assert.equal(prompt.operation(passwordOnly, { action: "update", name: "Alice", username: "" }).fields.username, "alice");
    assert.equal(prompt.operation(passwordOnly, { action: "update", name: "Alice", username: "alice2" }).fields.username, "alice2");
});

test("a login chosen from a vault search becomes the update target and gains this site", () => {
    const siteAccounts = [{ id: 3, revision: 1, name: "Site login", username: "bob" }];
    const data = prompt.describe(siteAccounts, "alice", "https://login.example.com");
    const chosen = prompt.chooseTarget(
        data,
        { id: 7, revision: 4, name: "Example", username: "alice", urls: ["https://www.example.com"] },
        siteAccounts,
        "alice"
    );
    assert.deepEqual(chosen.updateTarget, { id: 7, revision: 4, name: "Example", username: "alice", addSite: true });
    assert.equal(chosen.hasAccounts, true);
    assert.equal(chosen.preferUpdate, true);
    assert.match(chosen.updateNote, /address will be added to “Example”/);
    assert.doesNotMatch(chosen.updateNote, /keeps the username/, "same username: nothing else to explain");
    const { action, fields } = prompt.operation(
        { domain: "https://login.example.com", sessionId: "s", username: "alice", password: "new-secret", data: chosen },
        { action: "update", name: "ignored", username: "alice" }
    );
    assert.equal(action, "update");
    assert.deepEqual(
        { entryId: fields.entryId, expectedRevision: fields.expectedRevision, addDomain: fields.addDomain, username: fields.username },
        { entryId: 7, expectedRevision: 4, addDomain: true, username: "alice" }
    );

    // A login already saved for this site keeps its addresses.
    const sameSite = prompt.chooseTarget(data, siteAccounts[0], siteAccounts, "alice");
    assert.equal(sameSite.updateTarget.addSite, false);
    assert.match(sameSite.updateNote, /keeps the username “bob”/);
    assert.doesNotMatch(sameSite.updateNote, /address will be added/);
    const update = prompt.operation(
        { domain: "https://login.example.com", sessionId: "s", username: "alice", password: "p", data: sameSite },
        { action: "update", name: "x", username: "alice" }
    );
    assert.equal(update.fields.addDomain, undefined);
    assert.equal(update.fields.username, "bob", "the captured username never renames another login");
    assert.throws(() => prompt.chooseTarget(data, { id: 0 }, siteAccounts, "alice"), /Choose a saved login/);
});
