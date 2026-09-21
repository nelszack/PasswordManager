const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
    testDir: "./extension/e2e",
    fullyParallel: false,
    workers: 1,
    retries: process.env.CI ? 1 : 0,
    timeout: 30_000,
    use: {
        trace: "retain-on-failure",
        screenshot: "only-on-failure"
    },
    reporter: process.env.CI ? [["line"], ["html", { open: "never" }]] : "line"
});
