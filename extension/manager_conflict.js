"use strict";
// Reapply explicit local edits to a reviewed revision; never send a mutation here.
function canonical(value) {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
    return value ?? "";
}
const same = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
function rebase(original, latest, local) {
    if (original.id !== latest.id) throw new Error("The reviewed item changed. Review it again.");
    const merged = { password: local.password };
    for (const key of ["name", "kind", "username", "notes", "urls"]) {
        merged[key] = same(local[key], original[key]) ? latest[key] : local[key];
    }
    const fields = new Map(latest.fields.map(field => [field.name.toLowerCase(), { ...field }]));
    for (const name of local.removeFields) fields.delete(name.toLowerCase());
    for (const field of local.fields) {
        const before = original.fields.find(old => old.name.toLowerCase() === field.name.toLowerCase());
        if (!before || !same(before, field)) fields.set(field.name.toLowerCase(), { ...field });
    }
    merged.fields = [...fields.values()];
    return merged;
}
function summary(original, latest, local) {
    const preview = value => String(value ?? "(empty)").slice(0, 240);
    const rows = [];
    for (const key of ["name", "kind", "username", "notes", "urls"]) {
        if (!same(local[key], original[key])) rows.push(`${key}${same(latest[key], original[key]) ? "" : " (also changed elsewhere)"}\nOriginal: ${preview(original[key])}\nLatest: ${preview(latest[key])}\nYour edit: ${preview(local[key])}`);
    }
    if (local.password) rows.push("Primary secret: your replacement will replace the latest stored value. Values stay hidden.");
    for (const field of local.fields) {
        const before = original.fields.find(old => old.name.toLowerCase() === field.name.toLowerCase());
        if (!before || !same(before, field)) {
            const remote = latest.fields.find(old => old.name.toLowerCase() === field.name.toLowerCase());
            const secret = field.secret || before?.secret || remote?.secret;
            rows.push(`Field ${field.name}: ${secret ? "secret values stay hidden; your change replaces the latest field" : `latest ${preview(remote?.value)} → your edit ${preview(field.value)}`}`);
        }
    }
    for (const name of local.removeFields) rows.push(`Remove field: ${name}`);
    return rows.join("\n\n") || "No explicit local edits to reapply.";
}
module.exports = { rebase, summary };
