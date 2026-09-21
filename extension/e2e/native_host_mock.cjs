#!/usr/bin/env node

const fs = require("node:fs");

const logPath = process.env.PM_E2E_NATIVE_LOG;
let buffered = Buffer.alloc(0);
let accounts = [];

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
        if (accounts.length === 0) {
            write({ id: request.id, success: false, error: "Not found." });
        } else {
            write({ id: request.id, success: true, data: JSON.stringify(accounts) });
        }
    } else if (request.action === "saveCredentials") {
        accounts.push({
            id: 7,
            name: request.name,
            username: request.username,
            password: request.password,
            has_totp: false
        });
        write({ id: request.id, success: true, data: "Saved." });
    } else if (request.action === "updateCredentials") {
        accounts = accounts.map(account => account.id === request.entryId
            ? { ...account, username: request.username, password: request.password }
            : account);
        write({ id: request.id, success: true, data: "Saved." });
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
