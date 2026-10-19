#!/usr/bin/env node

const fs = require("node:fs");

const logPath = process.env.PM_E2E_NATIVE_LOG;
const mode = process.env.PM_E2E_NATIVE_MODE || "normal";
let locked = mode === "locked";
let buffered = Buffer.alloc(0);
let accounts = JSON.parse(process.env.PM_E2E_NATIVE_ACCOUNTS || "[]").map(item => ({ revision: 1, kind: "login", urls: [], username: null, has_totp: false, has_duo: false, ...item }));
const autofillItems = JSON.parse(process.env.PM_E2E_NATIVE_AUTOFILL_ITEMS || "[]");
const contract = require("../command_contract.js");
const statePath = logPath ? `${logPath}.state.json` : null;
let activeRequest, outcomes = {};
let duoRequests = JSON.parse(process.env.PM_E2E_NATIVE_DUO_REQUESTS || "[]");

function write(response) {
    response.protocolVersion = contract.protocolVersion;
    if (activeRequest?.operationId && contract.operations[activeRequest.action]?.mutates) {
        const operationId = activeRequest.operationId;
        const outcome = { operationId, state: response.success ? "committed" : "failed", revision: null };
        outcomes[operationId] = outcome;
        response.operation = outcome;
        if (statePath) fs.writeFileSync(statePath, JSON.stringify({ locked, accounts, duoRequests, outcomes }));
        if (mode === "lost-save" && activeRequest.action === "saveCredentials") return;
    }
    const payload = Buffer.from(JSON.stringify(response));
    const length = Buffer.alloc(4);
    length.writeUInt32LE(payload.length);
    process.stdout.write(Buffer.concat([length, payload]));
}

function handle(request) {
    activeRequest = request;
    if (statePath && fs.existsSync(statePath)) {
        ({ locked, accounts, duoRequests, outcomes } = JSON.parse(fs.readFileSync(statePath, "utf8")));
    }
    if (logPath) {
        fs.appendFileSync(logPath, `${JSON.stringify(request)}\n`);
    }
    if (request.action === "operationStatus") {
        write({ id: request.id, success: true, data: outcomes[request.operationId] || { operationId: request.operationId, state: "unknown", revision: null } });
    } else if (request.action === "status") {
        write({
            id: request.id,
            success: true,
            nativeVersion: "0.1.0",
            data: { locked, version: "0.1.0", warning: null }
        });
    } else if (["getCredentials", "getLoginItems", "getLoginItem", "getDuoItems"].includes(request.action)) {
        if (mode === "timeout") return;
        if (locked) {
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
        let matches = request.action === "getDuoItems"
            ? accounts.filter(account => account.has_duo === true && account.duo_origin === request.domain)
                .map(({ password, ...summary }) => summary)
            : accounts.filter(account => !account.domain || account.domain === request.domain);
        if (request.action === "getLoginItems") matches = matches.map(({ password, ...summary }) => summary);
        if (request.action === "getLoginItem") matches = matches.filter(account => account.id === request.entryId);
        if (matches.length === 0) {
            write({ id: request.id, success: false, error: "Not found." });
        } else {
            write({ id: request.id, success: true, data: request.action === "getLoginItem" ? matches[0] : matches });
        }
    } else if (request.action === "lock") {
        locked = true;
        write({ id: request.id, success: true, data: "Locked" });
    } else if (request.action === "managerDuoRequests") {
        write({ id: request.id, success: true, data: duoRequests.filter(r => r.entryId === request.entryId) });
    } else if (request.action === "managerDuoRespond") {
        if (process.env.PM_E2E_NATIVE_DUO_ERROR) {
            write({ id: request.id, success: false, error: process.env.PM_E2E_NATIVE_DUO_ERROR });
            return;
        }
        duoRequests = duoRequests.filter(r => r.id !== request.requestId || r.entryId !== request.entryId);
        write({ id: request.id, success: true, data: request.approve ? "Approved" : "Denied" });
    } else if (request.action === "getAutofillItems") {
        write({ id: request.id, success: true, data:
            autofillItems.map(({ id, name, kind, username }) => ({ id, revision: 1, name, kind, username: username || null, urls: [], has_totp: false, has_duo: false }))
         });
    } else if (request.action === "getAutofillItem") {
        const item = autofillItems.find(item => item.id === request.entryId);
        write(item ? { id: request.id, success: true, data: { revision: 1, username: null, custom_fields: [], ...item } }
            : { id: request.id, success: false, error: "Not found." });
    } else if (request.action === "saveCredentials") {
        accounts.push({
            id: 7 + accounts.length, revision: 1, kind: "login", urls: [request.domain], has_duo: false,
            name: request.name,
            username: request.username,
            password: request.password,
            has_totp: false,
            domain: request.domain
        });
        write({ id: request.id, success: true, data: "Saved." });
    } else if (request.action === "updateCredentials") {
        accounts = accounts.map(account => account.id === request.entryId
            ? { ...account, revision: account.revision + 1, username: request.username, password: request.password }
            : account);
        write({ id: request.id, success: true, data: "Saved." });
    } else if (request.action === "getTotp") {
        write({
            id: request.id,
            success: true,
            data: { mode: "totp", code: "123456", expires_in: 24, counter: null }
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
