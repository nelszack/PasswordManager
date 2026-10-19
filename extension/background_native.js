// The daemon owns mutation identity. Timeouts never replay a sent operation.
const PasswordManagerBackgroundNative = {
    create({ chrome, protocol, contract = globalThis.PasswordManagerCommandContract,
        onDisconnect, setTimeout, clearTimeout, crypto = globalThis.crypto,
        idleTimeoutMs = 20_000, recoveryGraceMs = 1000 }) {
        const NATIVE_HOST = "com.myproject.password_manager";
        const channels = new Map(["control", "work", "duo"].map(name => [name,
            { name, port: null, active: null, queue: [], idleTimer: null, recoveryTimer: null }]));
        const unresolved = new Map();
        const observedUnknown = new Set();
        const storageKey = "pmUnresolvedOperations";
        let nextRequestId = 1;
        const session = chrome.storage?.session;
        let initialized = !session, restoreError = null;
        let storageOperations = Promise.resolve();
        const ready = session ? new Promise(resolve => session.get(storageKey, stored => {
            if (chrome.runtime.lastError) restoreError = new Error("Could not restore operation recovery state");
            for (const record of Array.isArray(stored?.[storageKey]) ? stored[storageKey] : []) {
                if (typeof record.operationId === "string" && contract.operations[record.action]?.mutates) unresolved.set(record.operationId, { operationId: record.operationId, action: record.action });
            }
            initialized = true; resolve();
        })) : Promise.resolve();
        function persist() {
            if (!session) return Promise.resolve();
            const snapshot = [...unresolved.values()];
            const write = storageOperations.catch(() => {}).then(() => new Promise((resolve, reject) => {
                session.set({ [storageKey]: snapshot }, () => {
                    const message = chrome.runtime.lastError?.message;
                    if (message) reject(new Error(message)); else resolve();
                });
            }));
            storageOperations = write;
            return write;
        }
        function remember(pending) {
            if (!pending.operationId) return;
            unresolved.set(pending.operationId, { operationId: pending.operationId, action: pending.action });
            persist().catch(() => {});
        }
        function forget(operationId) { observedUnknown.delete(operationId); if (unresolved.delete(operationId)) persist().catch(() => {}); }
        function failure(pending, message) {
            const uncertain = pending.sent && pending.policy.mutates;
            if (uncertain) remember(pending);
            else if (pending.operationId) forget(pending.operationId);
            const error = new Error(uncertain ? `${message}. The operation may still complete. Review its outcome before retrying.` : message);
            Object.assign(error, { uncertain, operationId: uncertain ? pending.operationId : undefined, operationAction: uncertain ? pending.action : undefined });
            return error;
        }
        function clearTimers(channel) {
            clearTimeout(channel.idleTimer); clearTimeout(channel.recoveryTimer);
            channel.idleTimer = channel.recoveryTimer = null;
        }
        function disconnected(channel, port, message, intentional = false) {
            if (channel.port !== port) return;
            channel.port = null; clearTimers(channel);
            const requests = [channel.active, ...channel.queue].filter(Boolean);
            channel.active = null; channel.queue = [];
            for (const pending of requests) {
                clearTimeout(pending.timer);
                pending.reject(failure(pending, message || "Native messaging host disconnected"));
            }
            if (!intentional && channel.name !== "duo") onDisconnect();
        }
        function close(channel, reason, intentional = false) {
            const port = channel.port;
            if (!port) return;
            disconnected(channel, port, reason, intentional);
            try { port.disconnect(); } catch (_) { /* Already closed. */ }
        }
        function idle(channel) {
            if (!idleTimeoutMs || channel.active || channel.queue.length || !channel.port) return;
            clearTimeout(channel.idleTimer);
            channel.idleTimer = setTimeout(() => close(channel, "Idle native connection closed", true), idleTimeoutMs);
        }
        function connect(channel) {
            clearTimeout(channel.idleTimer); channel.idleTimer = null;
            if (channel.port) return channel.port;
            const port = chrome.runtime.connectNative(NATIVE_HOST);
            channel.port = port;
            port.onMessage.addListener(response => {
                const pending = channel.active;
                if (channel.port !== port || !pending || pending.id !== response?.id) return;
                clearTimeout(pending.timer); clearTimeout(channel.recoveryTimer); channel.recoveryTimer = null;
                channel.active = null;
                try {
                    protocol.validateResponse(response, contract.protocolVersion, pending.operationId);
                    if (response.success) contract.validateResult(pending.action, response.data);
                    if (response.uncertain) remember(pending);
                    else if (pending.operationId) forget(pending.operationId);
                    pending.resolve({ ...response, ...(response.uncertain ? { operationId: pending.operationId, operationAction: pending.action } : {}) });
                } catch (error) { pending.reject(failure(pending, error.code === "protocol_mismatch" ? error.message : "Invalid native host response")); }
                pump(channel);
            });
            port.onDisconnect.addListener(() => disconnected(channel, port, chrome.runtime.lastError?.message));
            return port;
        }
        function pump(channel) {
            if (channel.active) return;
            if (!channel.queue.length) { idle(channel); return; }
            const pending = channel.queue.shift();
            if (pending.policy.mutates && pending.action !== "lock" && unresolved.size) {
                clearTimeout(pending.timer);
                pending.reject(Object.assign(new Error("A previous operation must be reconciled before another change"), { uncertain: true, operationId: unresolved.keys().next().value, operationAction: unresolved.values().next().value.action }));
                pump(channel); return;
            }
            channel.active = pending;
            function send() {
                if (channel.active !== pending || pending.expired) return;
                try {
                    const port = connect(channel);
                    port.postMessage({ ...pending.fields, id: pending.id, action: pending.action });
                    pending.sent = true; pending.fields = null;
                } catch (error) {
                    channel.active = null; clearTimeout(pending.timer);
                    pending.reject(failure(pending, error.message)); pump(channel);
                }
            }
            if (pending.operationId && session) {
                // Persist identity before sending; browser crashes must not erase an
                // accepted mutation's reconciliation obligation. No secrets are stored.
                unresolved.set(pending.operationId, { operationId: pending.operationId, action: pending.action });
                persist().then(send, () => {
                    if (channel.active !== pending) return;
                    channel.active = null; clearTimeout(pending.timer);
                    pending.reject(failure(pending, "Could not retain operation identity")); pump(channel);
                });
            } else send();
        }
        function enqueue(action, fields) {
            const policy = contract.operations[action];
            if (!policy) return Promise.reject(new Error("Unsupported native operation"));
            if (policy.mutates && restoreError) return Promise.reject(restoreError);
            const channel = channels.get(policy.lane || "work");
            if (channel.queue.length >= 32) return Promise.reject(new Error("Too many pending native requests"));
            const operationId = policy.mutates ? fields.operationId || crypto.randomUUID() : undefined;
            fields = Object.fromEntries(Object.entries({ ...fields, ...(operationId ? { operationId } : {}) }).filter(([key, value]) => value !== undefined && !["id", "action"].includes(key)));
            try { contract.validateRequest(action, fields); } catch (error) { return Promise.reject(error); }
            return new Promise((resolve, reject) => {
                const pending = { id: nextRequestId++, action, policy, operationId,
                    fields: { ...fields, ...(operationId ? { operationId } : {}) }, sent: false, resolve, reject };
                pending.timer = setTimeout(() => {
                    pending.expired = true;
                    const queued = channel.queue.indexOf(pending);
                    if (queued >= 0) channel.queue.splice(queued, 1);
                    pending.fields = null;
                    reject(failure(pending, pending.sent ? "Native messaging request timed out" : "Native request expired before it was sent"));
                    if (channel.active === pending && !pending.sent) {
                        channel.active = null; pump(channel);
                    } else if (channel.active === pending && !channel.recoveryTimer) {
                        // Bound a silent live port without assuming its mutation failed.
                        channel.recoveryTimer = setTimeout(() => close(channel, "Native connection recovery deadline elapsed"), recoveryGraceMs);
                    }
                }, policy.timeoutMs);
                channel.queue.push(pending); pump(channel);
            });
        }
        function request(action, fields = {}) {
            return initialized ? enqueue(action, fields) : ready.then(() => enqueue(action, fields));
        }
        async function reconcile(operationId) {
            const response = await request("operationStatus", { operationId });
            if (response.success) {
                if (response.data.operationId !== operationId) throw new Error("Operation review returned a different identity");
                if (["committed", "committed_durability_unknown", "failed"].includes(response.data.state)) forget(operationId);
                else if (response.data.state === "unknown") observedUnknown.add(operationId);
                else observedUnknown.delete(operationId);
            }
            return response;
        }
        function acknowledgeUnknown(operationId) {
            if (!unresolved.has(operationId) || !observedUnknown.has(operationId)) throw new Error("Only an explicitly reviewed unknown operation can be acknowledged");
            forget(operationId);
            return { success: true };
        }
        return { request, reconcile, acknowledgeUnknown, unresolved: () => [...unresolved.values()],
            closeIdle: () => { for (const channel of channels.values()) if (!channel.active && !channel.queue.length) close(channel, "Idle native connection closed", true); } };
    }
};
if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundNative;
