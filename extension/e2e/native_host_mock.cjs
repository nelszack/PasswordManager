#!/usr/bin/env node

const fs = require("node:fs");

const logPath = process.env.PM_E2E_NATIVE_LOG;
const mode = process.env.PM_E2E_NATIVE_MODE || "normal";
let buffered = Buffer.alloc(0);
let accounts = JSON.parse(process.env.PM_E2E_NATIVE_ACCOUNTS || "[]");

function write(response) {
    const payload = Buffer.from(JSON.stringify(response));
    const length = Buffer.alloc(4);
    length.writeUInt32LE(payload.length);
    process.stdout.write(Buffer.concat([length, payload]));
}

function handle(request) {
    if (logPath) {
        fs.appendFileSync(logPath, `${JSON.stringify(request)}\n`);
    }
    if (request.action === "status") {
        write({ id: request.id, success: true, data: "Status: unlocked" });
    } else if (request.action === "getCredentials") {
        if (mode === "timeout") return;
        if (mode === "locked") {
            write({ id: request.id, success: false, error: "Vault is locked" });
            return;
        }
        if (mode === "unavailable") {
            write({ id: request.id, success: false, error: "Server is unavailable" });
            return;
        }
        if (mode === "malformed") {
            write({ id: request.id, success: true, data: "not-json" });
            return;
        }
        const matches = accounts.filter(account => !account.domain || account.domain === request.domain);
        if (matches.length === 0) {
            write({ id: request.id, success: false, error: "Not found." });
        } else {
            write({ id: request.id, success: true, data: JSON.stringify(matches) });
        }
    } else if (request.action === "saveCredentials") {
        accounts.push({
            id: 7 + accounts.length,
            name: request.name,
            username: request.username,
            password: request.password,
            has_totp: false,
            domain: request.domain
        });
        write({ id: request.id, success: true, data: "Saved." });
    } else if (request.action === "updateCredentials") {
        accounts = accounts.map(account => account.id === request.entryId
            ? { ...account, username: request.username, password: request.password }
            : account);
        write({ id: request.id, success: true, data: "Saved." });
    } else if (request.action === "getTotp") {
        write({
            id: request.id,
            success: true,
            data: { code: "123456", expires_in: 24 }
        });
    } else {
        write({ id: request.id, success: false, error: "Unsupported test action" });
    }
}

process.stdin.on("data", chunk => {
    buffered = Buffer.concat([buffered, chunk]);
    while (buffered.length >= 4) {
        const length = buffered.readUInt32LE(0);
        if (buffered.length < length + 4) return;
        const payload = buffered.subarray(4, length + 4);
        buffered = buffered.subarray(length + 4);
        try {
            handle(JSON.parse(payload.toString("utf8")));
        } catch (error) {
            write({ id: null, success: false, error: error.message });
        }
    }
});
