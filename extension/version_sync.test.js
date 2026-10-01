const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("extension release metadata matches the password manager package", () => {
    const manifest = require("./manifest.json");
    const cargo = fs.readFileSync(path.resolve(__dirname, "../Cargo.toml"), "utf8");
    const packageVersion = cargo.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
    assert.ok(packageVersion, "Cargo package version is missing");
    assert.equal(manifest.version_name, packageVersion);
});
