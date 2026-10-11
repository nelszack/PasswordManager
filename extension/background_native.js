// Own state per worker instance; browser services are supplied by background.js.
const PasswordManagerBackgroundNative = {
    create({ chrome, protocol, onDisconnect, setTimeout, clearTimeout }) {
        const NATIVE_HOST = "com.myproject.password_manager";
        const REQUEST_TIMEOUT_MS = 7000;
        const DUO_REQUEST_TIMEOUT_MS = 60000;
        let nativePort = null, duoPort = null;
        let nextRequestId = 1;
        const pendingRequests = new Map();
        function closeNativePort(error) {
            onDisconnect();
            const message = error || "Native messaging host disconnected";
            for (const pending of pendingRequests.values()) {
                clearTimeout(pending.timer);
                pending.reject(new Error(message));
            }
            pendingRequests.clear();
            nativePort = null;
        }

        function connectNativeHost(duo) {
            if (duo ? duoPort : nativePort) return duo ? duoPort : nativePort;

            const port = chrome.runtime.connectNative(NATIVE_HOST);
            if (duo) duoPort = port; else nativePort = port;
            port.onMessage.addListener((response) => {
                const pending = pendingRequests.get(response?.id);
                if (!pending || pending.duo !== duo) return;
                clearTimeout(pending.timer);
                pendingRequests.delete(response.id);
                try {
                    pending.resolve(protocol.validateResponse(response));
                } catch (error) {
                    pending.reject(error);
                }
            });
            port.onDisconnect.addListener(() => {
                const error = chrome.runtime.lastError?.message;
                if (duo && duoPort === port) {
                    duoPort = null;
                    for (const [id, pending] of pendingRequests) {
                        if (!pending.duo) continue;
                        clearTimeout(pending.timer); pendingRequests.delete(id);
                        pending.reject(new Error(error || "Duo native messaging host disconnected"));
                    }
                } else if (!duo && nativePort === port) closeNativePort(error);
            });
            return port;
        }

        function nativeRequest(action, fields = {}) {
            return new Promise((resolve, reject) => {
                const id = nextRequestId++;
                const duo = ["managerDuoRequests", "managerDuoRespond"].includes(action);
                // Keep lock/status independent of the native host handling Duo.
                const timeout = duo ? DUO_REQUEST_TIMEOUT_MS : REQUEST_TIMEOUT_MS;
                const timer = setTimeout(() => {
                    pendingRequests.delete(id);
                    reject(new Error("Native messaging request timed out"));
                }, timeout);
                pendingRequests.set(id, { resolve, reject, timer, duo });

                try {
                    connectNativeHost(duo).postMessage({ id, action, ...fields });
                } catch (error) {
                    clearTimeout(timer);
                    pendingRequests.delete(id);
                    reject(error);
                }
            });
        }

        return { request: nativeRequest };
    }
};

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundNative;
