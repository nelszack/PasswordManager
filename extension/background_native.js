// Own state per worker instance; browser services are supplied by background.js.
const PasswordManagerBackgroundNative = {
    create({ chrome, protocol, onDisconnect, setTimeout, clearTimeout }) {
        const NATIVE_HOST = "com.myproject.password_manager";
        const REQUEST_TIMEOUT_MS = 7000;
        let nativePort = null;
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

        function connectNativeHost() {
            if (nativePort) return nativePort;

            const port = chrome.runtime.connectNative(NATIVE_HOST);
            nativePort = port;
            port.onMessage.addListener((response) => {
                const pending = pendingRequests.get(response?.id);
                if (!pending) return;
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
                if (nativePort === port) closeNativePort(error);
            });
            return port;
        }

        function nativeRequest(action, fields = {}) {
            return new Promise((resolve, reject) => {
                const id = nextRequestId++;
                const timer = setTimeout(() => {
                    pendingRequests.delete(id);
                    reject(new Error("Native messaging request timed out"));
                }, REQUEST_TIMEOUT_MS);
                pendingRequests.set(id, { resolve, reject, timer });

                try {
                    connectNativeHost().postMessage({ id, action, ...fields });
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
