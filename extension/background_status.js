// Own state per worker instance; browser services are supplied by background.js.
const PasswordManagerBackgroundStatus = {
    create({ chrome, nativeRequest, state, version, invalidate, cleanupExpired, setInterval }) {
        const STATUS_POLL_ALARM = "status-poll";
        const LIVE_STATUS_POLL_MS = 2000;
        let cachedStatus = null;
        let statusRefresh = null;
        chrome.runtime.onInstalled.addListener(() => {
            startStatusMonitoring();
        });

        chrome.runtime.onStartup.addListener(() => {
            startStatusMonitoring();
        });

        function startStatusMonitoring() {
            chrome.alarms.create(STATUS_POLL_ALARM, { periodInMinutes: 1 });
            refreshStatus();
        }

        chrome.alarms.onAlarm.addListener((alarm) => {
            if (alarm.name === STATUS_POLL_ALARM) {
                cleanupExpired();
                refreshStatus();
            }
        });

        function setBadge(status) {
            const { text, color, title } = state.badge(status);
            chrome.action.setBadgeText({ text });
            chrome.action.setBadgeBackgroundColor({ color });
            chrome.action.setTitle({ title });
        }

        function sameStatus(left, right) {
            return state.equal(left, right);
        }

        function publishStatus(status) {
            if (!status.native || !status.running || status.locked) {
                invalidate();
            }
            setBadge(status);
            if (sameStatus(cachedStatus, status)) return;

            cachedStatus = status;
            chrome.storage.local.set({ pmStatus: status });
            chrome.runtime.sendMessage(
                { action: "statusChanged", status },
                () => void chrome.runtime.lastError
            );
        }

        async function serverStatus() {
            try {
                const response = await nativeRequest("status");
                if (!response.success) {
                    const status = {
                        native: true, running: false, locked: false, error: response.error,
                        extensionVersion: version,
                        nativeVersion: response.nativeVersion
                    };
                    return { ...status, versionError: state.versionError(status) };
                }
                const status = {
                    native: true,
                    running: true,
                    extensionVersion: version,
                    nativeVersion: response.nativeVersion,
                    ...state.parseServerStatus(response.data)
                };
                return { ...status, versionError: state.versionError(status) };
            } catch (error) {
                return {
                    native: false, running: false, locked: false, error: error.message,
                    extensionVersion: version
                };
            }
        }

        function refreshStatus() {
            if (statusRefresh) return statusRefresh;
            statusRefresh = serverStatus()
                .then(status => {
                    publishStatus(status);
                    return status;
                })
                .finally(() => {
                    statusRefresh = null;
                });
            return statusRefresh;
        }

        function start() {
            // The native port keeps the worker alive; alarms cover suspension/restart.
            setInterval(refreshStatus, LIVE_STATUS_POLL_MS);
            startStatusMonitoring();
        }

        return { refresh: refreshStatus, start };
    }
};

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundStatus;
