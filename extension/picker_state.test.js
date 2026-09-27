const test = require("node:test");
const assert = require("node:assert/strict");
const picker = require("./picker_state.js");

test("picker derives safe titles, labels, and empty states", () => {
    assert.equal(picker.title("payment-card"), "Choose payment card");
    assert.equal(picker.title("unknown"), "Password Manager");
    assert.equal(picker.itemLabel({ name: "Primary", username: "alice" }), "Primary");
    assert.equal(picker.itemLabel({ username: "alice" }), "alice");
    assert.equal(picker.itemLabel({}), "Unnamed item");
    assert.equal(picker.status([]), "No matching items");
    assert.equal(picker.status([{}]), "Select an item to fill");
});
