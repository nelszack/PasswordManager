// Each host is sequential. Queue locally so expired work is never sent later.
const PasswordManagerBackgroundNative = {
    create({ chrome, protocol, onDisconnect, setTimeout, clearTimeout }) {
        const NATIVE_HOST = "com.myproject.password_manager";
        const mutations = new Set(["managerUnlock", "managerAdd", "managerUpdate", "managerDelete",
            "managerCopy", "saveCredentials", "updateCredentials", "getTotp", "managerDuoRespond", "lock"]);
        const channels = new Map(["control", "work", "duo"].map(name => [name, { name, port: null, active: null, queue: [] }]));
        let nextRequestId = 1;

        function failure(pending, message) {
            const uncertain = pending.sent && mutations.has(pending.action);
            const error = new Error(uncertain
                ? `${message}. The operation may still complete. Review the vault before retrying.`
                : message);
            error.uncertain = uncertain;
            return error;
        }

        function disconnected(channel, port, message) {
            if (channel.port !== port) return;
            channel.port = null;
            const requests = [channel.active, ...channel.queue].filter(Boolean);
            channel.active = null; channel.queue = [];
            for (const pending of requests) {
                clearTimeout(pending.timer);
                pending.reject(failure(pending, message || "Native messaging host disconnected"));
            }
            if (channel.name !== "duo") onDisconnect();
        }

        function connect(channel) {
            if (channel.port) return channel.port;
            const port = chrome.runtime.connectNative(NATIVE_HOST);
            channel.port = port;
            port.onMessage.addListener(response => {
                const pending = channel.active;
                if (channel.port !== port || !pending || pending.id !== response?.id) return;
                clearTimeout(pending.timer);
                channel.active = null;
                try { pending.resolve(protocol.validateResponse(response)); }
                catch (_) { pending.reject(failure(pending, "Invalid native host response")); }
                pump(channel);
            });
            port.onDisconnect.addListener(() => disconnected(channel, port, chrome.runtime.lastError?.message));
            return port;
        }

        function pump(channel) {
            if (channel.active || !channel.queue.length) return;
            const pending = channel.queue.shift();
            channel.active = pending;
            try {
                const port = connect(channel);
                port.postMessage({ ...pending.fields, id: pending.id, action: pending.action });
                pending.sent = true;
                // Do not keep an extra copy of secrets while waiting for a reply.
                pending.fields = null;
            } catch (error) {
                channel.active = null;
                clearTimeout(pending.timer);
                pending.reject(failure(pending, error.message));
                pump(channel);
            }
        }

        function request(action, fields = {}) {
            const name = ["status", "lock"].includes(action) ? "control"
                : ["managerDuoRequests", "managerDuoRespond"].includes(action) ? "duo" : "work";
            const channel = channels.get(name);
            if (channel.queue.length >= 32) return Promise.reject(new Error("Too many pending native requests"));
            return new Promise((resolve, reject) => {
                const pending = { id: nextRequestId++, action, fields, sent: false, resolve, reject };
                pending.timer = setTimeout(() => {
                    const queued = channel.queue.indexOf(pending);
                    if (queued >= 0) channel.queue.splice(queued, 1);
                    pending.fields = null;
                    reject(failure(pending, pending.sent
                        ? "Native messaging request timed out" : "Native request expired before it was sent"));
                    // An active host must finish before queued work can run. A late
                    // reply releases the channel; it cannot resolve the expired call.
                }, name === "duo" ? 60000 : 7000);
                channel.queue.push(pending);
                pump(channel);
            });
        }
        return { request };
    }
};

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundNative;
