"use strict";
// Actual Chromium DOM + production observer/detection, with button rendering
// replaced by counters for discovery; controls_position measures real button geometry.
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("@playwright/test");
const root = path.resolve(__dirname, "..");
async function main() {
    const sizes = (process.env.PM_BENCH_SIZES || "100,1000,10000").split(",").map(Number);
    const samples = Number(process.env.PM_BENCH_SAMPLES || 9);
    const sampleMs = Number(process.env.PM_BENCH_SAMPLE_MS || 20);
    if (sizes.some(n => !Number.isInteger(n) || n < 1 || n > 100000) || !Number.isInteger(samples) || samples < 3 || samples > 100 || !Number.isInteger(sampleMs) || sampleMs < 1 || sampleMs > 1000) throw new Error("Invalid browser benchmark configuration");
    if (!process.env.PM_BENCH_OUTPUT) throw new Error("Use npm run bench -- --suite browser to choose a report destination");
    const browser = await chromium.launch({ channel: "chromium", headless: true });
    try {
        const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
        const page = await context.newPage();
        page.setDefaultTimeout(120000);
        await page.setContent("<!doctype html><html><body></body></html>");
        await page.addScriptTag({ path: path.join(root, "extension/content_detection.js") });
        await page.evaluate(() => {
            window.module = { exports: {} };
            window.require = name => {
                if (name !== "./content_detection.js") throw new Error(`Unexpected module ${name}`);
                return window.PasswordManagerContentDetection;
            };
        });
        await page.addScriptTag({ path: path.join(root, "extension/content_observer.js") });
        await page.evaluate(() => { window.createObserver = window.module.exports.create; delete window.module; delete window.require; });
        await page.evaluate(() => {
            window.module = { exports:{} };
            window.require = name => {
                if (name !== "./content_detection.js") throw new Error(`Unexpected module ${name}`);
                return window.PasswordManagerContentDetection;
            };
        });
        // CommonJS modules need their own lexical scope when injected as classic scripts.
        await page.addScriptTag({ content: `(function () {\n${fs.readFileSync(path.join(root, "extension/content_controls.js"), "utf8")}\n})();` });
        await page.evaluate(() => { window.createControls = window.module.exports.create; delete window.module; });
        for (const size of sizes) {
            const records = await page.evaluate(async ({ size, samples, sampleMs }) => {
                const mount = document.createElement("main");
                document.body.replaceChildren(mount);
                const fragment = document.createDocumentFragment();
                for (let i = 0; i < size; i++) fragment.append(document.createElement("span"));
                mount.append(fragment);
                let fields = 0;
                const makeForm = parent => {
                    const form = document.createElement("form");
                    for (const [type, autocomplete] of [["text", "username"], ["password", "current-password"]]) {
                        const input = document.createElement("input"); input.type = type; input.autocomplete = autocomplete;
                        form.append(input); fields++;
                    }
                    parent.append(form);
                };
                for (let i = 0; i < Math.max(1, Math.floor(size / 100)); i++) makeForm(mount);
                for (let i = 0; i < Math.max(1, Math.floor(size / 500)); i++) {
                    const host = document.createElement("div"); mount.append(host);
                    makeForm(host.attachShadow({ mode: "open" }));
                }
                const classified = new Map();
                const controls = {
                    createSecureTotpButton: input => classified.set(input, "totp"),
                    createSecureTypedButton: input => classified.set(input, "typed"),
                    createSecureCredentialButton: input => classified.set(input, "login"),
                    removeSecurePickerButton: input => classified.delete(input)
                };
                const create = () => window.createObserver({ controls,
                    generator: { createGeneratorButton() {}, removeGeneratorButton() {} },
                    autofill: { typedAutofillKind: () => null }
                });
                let queries = 0;
                const originals = [Element.prototype.querySelectorAll, Document.prototype.querySelectorAll, DocumentFragment.prototype.querySelectorAll];
                Element.prototype.querySelectorAll = function (selector) { if (selector === "*") queries++; return originals[0].call(this, selector); };
                Document.prototype.querySelectorAll = function (selector) { if (selector === "*") queries++; return originals[1].call(this, selector); };
                DocumentFragment.prototype.querySelectorAll = function (selector) { if (selector === "*") queries++; return originals[2].call(this, selector); };
                const originalFrame = window.requestAnimationFrame;
                let pending;
                window.requestAnimationFrame = callback => originalFrame.call(window, timestamp => {
                    const start = performance.now();
                    try { callback(timestamp); }
                    catch (error) { pending?.reject(error); return; }
                    if (pending) { const current = pending; pending = null; current.resolve((performance.now() - start) * 1e6); }
                });
                let observer;
                let marker;
                let turn = 0;
                async function update(structural) {
                    queries = 0;
                    const start = performance.now();
                    let timeout;
                    const duration_ns = await new Promise((resolve, reject) => {
                        timeout = setTimeout(() => { pending = null; reject(new Error("Observer did not process benchmark mutation")); }, 5000);
                        pending = { resolve, reject };
                        if (structural) { marker?.remove(); marker = document.createElement("span"); mount.append(marker); }
                        mount.className = `benchmark-${++turn % 2}`;
                    }).finally(() => clearTimeout(timeout));
                    if (classified.size !== fields) throw new Error(`Lost controls: ${classified.size}/${fields}`);
                    return { duration_ns, wall_ns: (performance.now() - start) * 1e6, queries };
                }
                const results = [];
                try {
                    for (const name of ["dom_initial", "dom_attributes", "dom_structural"]) {
                        if (name !== "dom_initial") { classified.clear(); observer = create(); observer.observeInputs(); }
                        const operation = name === "dom_initial" ? async () => {
                            classified.clear(); const next = create(); queries = 0;
                            const start = performance.now(); next.observeInputs(); const duration_ns = (performance.now() - start) * 1e6;
                            const count = queries; next.dispose();
                            if (classified.size !== fields) throw new Error(`Initial discovery missed controls: ${classified.size}/${fields}`);
                            return { duration_ns, wall_ns: duration_ns, queries: count };
                        } : () => update(name === "dom_structural");
                        let warm;
                        for (let i = 0; i < 3; i++) warm = await operation();
                        const iterations = Math.min(20, Math.max(1, Math.ceil(sampleMs * 1e6 / Math.max(1, warm.duration_ns))));
                        const means = [], wall = [], queryCounts = [];
                        for (let sample = 0; sample < samples; sample++) {
                            let cpuSum = 0, wallSum = 0, querySum = 0;
                            for (let i = 0; i < iterations; i++) {
                                const measured = await operation(); cpuSum += measured.duration_ns; wallSum += measured.wall_ns; querySum += measured.queries;
                            }
                            means.push(Math.max(1, cpuSum / iterations)); wall.push(wallSum / iterations); queryCounts.push(querySum / iterations);
                        }
                        const sampleOrder = [...means];
                        means.sort((a, b) => a - b); wall.sort((a, b) => a - b);
                        results.push({ schema_version: 1, suite: "browser", name, size, unit: "ns/op", samples,
                            iterations_per_sample: iterations, median_ns: (means[Math.floor((samples - 1) / 2)] + means[Math.floor(samples / 2)]) / 2, p95_ns: means[Math.ceil(samples * .95) - 1], min_ns: means[0], sample_means_ns: sampleOrder,
                            wall_median_ns: (wall[Math.floor((samples - 1) / 2)] + wall[Math.floor(samples / 2)]) / 2, descendant_queries_per_op: queryCounts.reduce((a, b) => a + b, 0) / samples,
                            controls: fields, shadow_roots: Math.max(1, Math.floor(size / 500)), optimized: null });
                        observer?.dispose(); observer = null;
                    }
                    // Real production controls and their animation-frame read/write batch.
                    const controls = window.createControls({ bridge:{}, credentials:{}, autofill:{} });
                    const inputs = [mount, ...mount.querySelectorAll("*")].flatMap(root =>
                        root.shadowRoot ? [...root.shadowRoot.querySelectorAll("input")] : root instanceof HTMLInputElement ? [root] : []);
                    try {
                        for (const input of inputs) controls.createSecureCredentialButton(input);
                        await new Promise(resolve => originalFrame.call(window, resolve));
                        const means=[], wall=[];
                        for (let sample=0;sample<samples;sample++) {
                            let timeout;
                            const start=performance.now();
                            const duration=await new Promise((resolve,reject)=> {
                                timeout=setTimeout(()=>{pending=null;reject(new Error("Position frame missing"));},5000);
                                pending={resolve,reject};
                                mount.style.paddingLeft=(sample%2)+"px";
                                window.dispatchEvent(new Event("resize"));
                            }).finally(()=>clearTimeout(timeout));
                            means.push(duration);wall.push((performance.now()-start)*1e6);
                        }
                        const ordered=[...means].sort((a,b)=>a-b);
                        wall.sort((a,b)=>a-b);
                        // Document queries do not cross the open shadow roots in this fixture.
                        if (inputs.some(input => !input.nextElementSibling?.classList.contains("my-extension-ui")
                            || !input.nextElementSibling.style.left)) throw new Error("Missing rendered controls");
                        results.push({schema_version:1,suite:"browser",name:"controls_position",size,unit:"ns/op",samples,
                            iterations_per_sample:1,median_ns:(ordered[Math.floor((samples-1)/2)]+ordered[Math.floor(samples/2)])/2,
                            min_ns:ordered[0],p95_ns:ordered[Math.ceil(samples*.95)-1],sample_means_ns:means,
                            wall_median_ns:wall[Math.floor(samples/2)],controls:inputs.length,optimized:null});
                    } finally { controls.dispose(); }
                    return results;
                } finally {
                    observer?.dispose(); pending = null;
                    Element.prototype.querySelectorAll = originals[0]; Document.prototype.querySelectorAll = originals[1]; DocumentFragment.prototype.querySelectorAll = originals[2];
                    window.requestAnimationFrame = originalFrame; document.body.replaceChildren();
                }
            }, { size, samples, sampleMs });
            for (const record of records) {
                record.browser = browser.version();
                fs.appendFileSync(process.env.PM_BENCH_OUTPUT, JSON.stringify(record) + "\n");
                console.log(`BENCH ${JSON.stringify(record)}`);
            }
        }
        await context.close();
    } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
