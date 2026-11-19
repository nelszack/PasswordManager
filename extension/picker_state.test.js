const test = require("node:test");
const assert = require("node:assert/strict");
const picker = require("./picker_state.js");

test("picker derives safe titles, labels, and empty states", () => {
    assert.equal(picker.title("payment-card"), "Choose a payment card");
    assert.equal(picker.title("unknown"), "Password Manager");
    assert.equal(picker.itemLabel({ name: "Primary", username: "alice" }), "Primary");
    assert.equal(picker.itemLabel({ username: "alice" }), "alice");
    assert.equal(picker.itemLabel({}), "Unnamed item");
    assert.equal(picker.status([]), "No saved items match this site");
    assert.match(picker.status([{}]), /Enter/);
    assert.equal(picker.initial({ name: " émile" }), "É");
    assert.equal(picker.initial({ name: "!!" }), "•");
});

test("picker ranks name prefixes before substrings and usernames", () => {
    const items = [
        { id: 1, name: "Work mail", username: "git@corp" },
        { id: 2, name: "My GitHub", username: "me" },
        { id: 3, name: "GitLab", username: "me" },
        { id: 4, name: "Bank", username: "x" },
    ];
    assert.deepEqual(picker.rank(items, " git ").map(item => item.id), [3, 2, 1]);
    assert.deepEqual(picker.rank(items, "").map(item => item.id), [1, 2, 3, 4]);
    assert.deepEqual(picker.rank(undefined, "x"), []);
});

test("picker keyboard movement wraps and supports Home/End", () => {
    assert.equal(picker.move(-1, 0, "ArrowDown"), -1);
    assert.equal(picker.move(-1, 3, "ArrowDown"), 0);
    assert.equal(picker.move(2, 3, "ArrowDown"), 0);
    assert.equal(picker.move(0, 3, "ArrowUp"), 2);
    assert.equal(picker.move(-1, 3, "ArrowUp"), 2);
    assert.equal(picker.move(2, 3, "ArrowUp"), 1);
    assert.equal(picker.move(1, 3, "Home"), 0);
    assert.equal(picker.move(1, 3, "End"), 2);
    assert.equal(picker.move(1, 3, "Tab"), 1);
});
