const test = require("node:test");
const assert = require("node:assert/strict");
const fields = require("./content_fields.js");

test("card fields are inferred from common accessible descriptors", () => {
    assert.equal(fields.inferCard(["Card number"]), "cc-number");
    assert.equal(fields.inferCard(["expiration month"]), "cc-exp-month");
    assert.equal(fields.inferCard(["CVV security code"]), "cc-csc");
    assert.equal(fields.inferCard(["unrelated"]), null);
});

test("identity fields cover names, addresses, and contact details", () => {
    assert.equal(fields.inferIdentity(["Given name"]), "given-name");
    assert.equal(fields.inferIdentity(["Apartment or suite"]), "address-line2");
    assert.equal(fields.inferIdentity(["ZIP code"]), "postal-code");
    assert.equal(fields.inferIdentity(["Telephone"]), "tel");
});

test("custom fields match normalized aliases without coercing missing data", () => {
    const custom = [{ name: "Card Security-Code", value: 123 }, { name: "Ignored", value: "x" }];
    assert.equal(fields.customValue(custom, ["card security code"]), "123");
    assert.equal(fields.customValue(null, ["card security code"]), "");
    assert.equal(fields.normalize(" Address_Line 1 "), "addressline1");
});

test("identity inference distinguishes county, country name, middle name and numbered addresses", () => {
    for (const [label, expected] of [
        ["County", "address-level3"], ["State", "address-level1"],
        ["Country name", "country-name"], ["Middle name", "additional-name"],
        ["address1", "address-line1"], ["address2", "address-line2"], ["address3", "address-line3"]
    ]) assert.equal(fields.inferIdentity([label]), expected);
});
