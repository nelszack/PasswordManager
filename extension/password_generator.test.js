const test = require("node:test");
const assert = require("node:assert/strict");
const generator = require("./password_generator.js");

test("configured generation honors exact lengths, enabled sets, and ambiguity filtering", () => {
    for (let i = 0; i < 50; i++) {
        const password = generator.generate({ length: 37, symbols: false });
        assert.equal(password.length, 37);
        assert.match(password, /^[A-HJ-NP-Za-km-np-z2-9]+$/);
        assert.match(password, /[A-Z]/); assert.match(password, /[a-z]/); assert.match(password, /[2-9]/);
        assert.equal(generator.generate({ length: 1 }).length, 1);
        assert.match(generator.generate({ uppercase: false, lowercase: false, digits: false, symbolSet: "?!", length: 12 }), /^[?!]{12}$/);
    }
    assert.throws(() => generator.generate({ uppercase: false, lowercase: false, digits: false, symbols: false }), /Enable/);
    for (const options of [{ length: 0 }, { length: 256 }, { length: 1.5 }, { words: 0 }, { symbolSet: "é" }, { separator: "\n" }, { digits: "yes" }]) {
        assert.throws(() => generator.validate(options), /Invalid/);
    }
});

test("passphrases use the configured word count and separator", () => {
    const result = generator.generate({ mode: "passphrase", words: 7, separator: "." });
    assert.equal(result.split(".").length, 7);
    assert.match(result, /^[a-z]+(?:\.[a-z]+){6}$/);
    assert.equal(generator.generate({ mode: "passphrase", words: 1 }).includes("-"), false);
});

test("site overrides match exact origins, preserve defaults, and reject unsafe destinations", () => {
    assert.equal(generator.siteOrigin("https://Example.COM:8443/"), "https://example.com:8443");
    for (const value of ["http://example.com", "https://user:password@example.com", "https://example.com/path", "https://example.com/?x=1", "not-a-url"]) assert.throws(() => generator.siteOrigin(value));
    const stored = { pmGenerator: { length: 25 }, pmGeneratorsByOrigin: { "https://example.com": { length: 31 } } };
    assert.equal(generator.settingsForSite(stored, "https://example.com/signup").length, 31);
    assert.equal(generator.settingsForSite(stored, "https://example.com:8443/signup").length, 25);
    assert.equal(generator.settingsForSite(stored, "https://login.example.com").length, 25);
    assert.equal(generator.settingsForSite({ pmGenerator: { length: 0 } }, "not-a-url").length, 20);
});
