// Loads every page in forms/ with the real extension and checks which in-page
// buttons each marked field receives, and that each button is drawn over its
// own field. See forms/README.md for the markup.
const { test, expect } = require("@playwright/test");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const { launchExtension } = require("./harness.cjs");

const FORMS = path.join(__dirname, "forms");
// Pages ending in -frame.html are only loaded inside another page.
const PAGES = fs.readdirSync(FORMS).filter(name => name.endsWith(".html") && !name.endsWith("-frame.html")).sort();
const BUTTON_KINDS = {
    "Choose saved credentials": "login",
    "Choose one-time code": "totp",
    "Generate a strong password": "generate",
    "Choose payment card": "card",
    "Choose identity": "identity"
};

function startServer() {
    const server = http.createServer((request, response) => {
        const name = path.basename(decodeURIComponent(new URL(request.url, "http://localhost").pathname));
        const file = path.join(FORMS, name);
        if (!name.endsWith(".html") || !fs.existsSync(file)) {
            response.writeHead(404).end();
            return;
        }
        response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        response.end(fs.readFileSync(file));
    });
    return new Promise(resolve => server.listen(0, "127.0.0.1", () => resolve(server)));
}

// Runs inside each frame. Walks the document and open shadow roots (the test
// copy of the extension opens its own roots) and attributes every shown
// extension button to the marked field under its center.
function collectInFrame(kinds) {
    const roots = [document];
    const marked = [];
    const inputs = [];
    const buttons = [];
    for (let index = 0; index < roots.length; index++) {
        for (const element of roots[index].querySelectorAll("*")) {
            if (element.localName === "pm-field-control") {
                const button = element.shadowRoot?.querySelector("button");
                const rect = button?.getBoundingClientRect();
                // Buttons parked off the page (with an off-screen field) are never seen.
                const onPage = rect && rect.right > 0 && rect.bottom > 0;
                if (button && rect.width && rect.height && onPage && getComputedStyle(element).display !== "none") {
                    buttons.push({
                        label: button.getAttribute("aria-label") || "",
                        x: rect.left + rect.width / 2,
                        y: rect.top + rect.height / 2
                    });
                }
                continue;
            }
            if (element.shadowRoot) roots.push(element.shadowRoot);
            if (element.hasAttribute("data-expect")) marked.push(element);
            if (["input", "select", "textarea"].includes(element.localName)) inputs.push(element);
        }
    }
    const describe = element => element.id ? `#${element.id}` : `${element.localName}[name="${element.getAttribute("name")}"]`;
    const contains = (element, point) => {
        const rect = element.getBoundingClientRect();
        return point.x >= rect.left && point.x <= rect.right && point.y >= rect.top && point.y <= rect.bottom;
    };
    const fields = marked.map(element => ({
        field: describe(element),
        expected: element.getAttribute("data-expect").split(/\s+/).filter(Boolean).sort(),
        knownIssue: element.getAttribute("data-known-issue"),
        actual: []
    }));
    const stray = [];
    for (const button of buttons) {
        const title = Object.keys(kinds).find(prefix => button.label.startsWith(prefix));
        const kind = title ? kinds[title] : `unknown button "${button.label}"`;
        const owner = marked.findIndex(element => contains(element, button));
        if (owner >= 0) {
            fields[owner].actual.push(kind);
        } else {
            const under = inputs.find(element => contains(element, button));
            stray.push(`${kind} button over ${under ? `unmarked field ${describe(under)}` : "no field"}` +
                ` at (${Math.round(button.x)}, ${Math.round(button.y)})`);
        }
    }
    for (const field of fields) field.actual.sort();
    return { fields, stray };
}

async function collect(page) {
    const results = { fields: [], stray: [] };
    for (const frame of page.frames()) {
        const prefix = frame === page.mainFrame() ? "" : `[${path.basename(new URL(frame.url()).pathname)}] `;
        const found = await frame.evaluate(collectInFrame, BUTTON_KINDS).catch(() => null);
        if (!found) continue;
        results.fields.push(...found.fields.map(field => ({ ...field, field: prefix + field.field })));
        results.stray.push(...found.stray.map(message => prefix + message));
    }
    return results;
}

const same = (left, right) => left.join(" ") === right.join(" ");
const list = kinds => kinds.length ? kinds.join(" ") : "(none)";

function problems({ fields, stray }) {
    if (!fields.length) return ["no marked fields (yet)"];
    const found = fields
        .filter(field => !field.knownIssue && !same(field.expected, field.actual))
        .map(field => `${field.field}: expected ${list(field.expected)}, got ${list(field.actual)}`);
    return [...found, ...stray];
}

test.describe("real-world form corpus", () => {
    let server;
    let browser;

    test.beforeAll(async () => {
        test.skip(process.platform !== "linux", "The CI native-host fixture targets Chromium on Linux");
        server = await startServer();
        browser = await launchExtension({});
    });
    test.afterAll(async () => {
        await browser?.close();
        await new Promise(resolve => server ? server.close(resolve) : resolve());
    });

    for (const name of PAGES) {
        test(name, async () => {
            const page = await browser.context.newPage();
            try {
                await page.goto(`http://127.0.0.1:${server.address().port}/${name}`);
                // Pages that build their form in steps hold this marker until done.
                await page.waitForFunction(() => !document.querySelector("[data-corpus-pending]"));
                let latest;
                // Controls attach after document_idle and follow later DOM changes.
                await expect.poll(async () => problems(latest = await collect(page)), {
                    message: `buttons on ${name}`,
                    timeout: 8000
                }).toEqual([]);
                const fixed = latest.fields.filter(field => field.knownIssue && same(field.expected, field.actual));
                expect(fixed.map(field => `${field.field}: known issue "${field.knownIssue}" is fixed; remove the marker`))
                    .toEqual([]);
                for (const field of latest.fields.filter(field => field.knownIssue)) {
                    test.info().annotations.push({
                        type: "known issue",
                        description: `${field.field}: ${field.knownIssue} (expected ${list(field.expected)}, got ${list(field.actual)})`
                    });
                }
            } finally {
                await page.close();
            }
        });
    }
});
