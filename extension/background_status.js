// Own state per worker instance; browser services are supplied by background.js.
const PasswordManagerBackgroundStatus = {
    create({
        chrome,
        nativeRequest,
        state,
        version,
        invalidate,
        cleanupExpired,
        setInterval,
        clearInterval = globalThis.clearInterval,
        closeIdle = () => {},
        protocolVersion,
        now = Date.now,
    }) {
        const STATUS_POLL_ALARM = "status-poll";
        const LIVE_STATUS_POLL_MS = 2000;
        let cachedStatus = null;
        let lastStatus = null;
        let lastStatusAt = -Infinity;
        let statusRefresh = null;
        let liveTimer = null;
        const views = new Set();
        chrome.runtime.onConnect?.addListener(port => {
            if (port.name !== "pm-ui") return;
            views.add(port);
            if (liveTimer === null) liveTimer = setInterval(refreshStatus, LIVE_STATUS_POLL_MS);
            refreshStatus();
            port.onDisconnect.addListener(() => {
                views.delete(port);
                if (!views.size) {
                    clearInterval(liveTimer);
                    liveTimer = null;
                    closeIdle();
                }
            });
        });
        chrome.runtime.onInstalled.addListener(() => {
            startStatusMonitoring();
        });

        chrome.runtime.onStartup.addListener(() => {
            startStatusMonitoring();
        });

        function startStatusMonitoring() {
            // Re-creating an existing alarm restarts its period, so a worker that
            // restarts more often than once a minute would never reach the alarm.
            const create = () => chrome.alarms.create(STATUS_POLL_ALARM, { periodInMinutes: 1 });
            if (typeof chrome.alarms.get !== "function") create();
            else
                chrome.alarms.get(STATUS_POLL_ALARM, alarm => {
                    void chrome.runtime.lastError;
                    if (alarm?.periodInMinutes !== 1) create();
                });
            refreshStatus();
        }

        chrome.alarms.onAlarm.addListener(alarm => {
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

        function available(status) {
            return Boolean(status?.native && status.running && !status.locked);
        }

        function publishStatus(status) {
            lastStatus = status;
            lastStatusAt = now();
            const previous = cachedStatus;
            // Invalidate only when the vault becomes unavailable or the unlock session
            // changes. A picker opened while already locked stays open with its
            // unlock guidance instead of being closed by every later refresh.
            if (
                (!available(status) && (previous === null || available(previous))) ||
                (previous?.sessionId && previous.sessionId !== status.sessionId)
            ) {
                invalidate();
            }
            if (sameStatus(previous, status)) return;

            cachedStatus = status;
            setBadge(status);
            chrome.storage.local.set({ pmStatus: status });
            chrome.runtime.sendMessage({ action: "statusChanged", status }, () => void chrome.runtime.lastError);
        }

        async function serverStatus() {
            try {
                const response = await nativeRequest("status");
                if (!response.success) {
                    const status = {
                        native: true,
                        running: false,
                        locked: false,
                        error: response.error,
                        extensionVersion: version,
                        nativeVersion: response.nativeVersion,
                        protocolVersion: response.protocolVersion,
                        extensionProtocolVersion: protocolVersion,
                    };
                    return { ...status, versionError: state.versionError(status) };
                }
                const status = {
                    native: true,
                    running: true,
                    sessionId: response.sessionId || null,
                    extensionVersion: version,
                    nativeVersion: response.nativeVersion,
                    protocolVersion: response.protocolVersion,
                    extensionProtocolVersion: protocolVersion,
                    ...state.parseServerStatus(response.data),
                };
                return { ...status, versionError: state.versionError(status) };
            } catch (error) {
                return {
                    native: false,
                    running: false,
                    locked: false,
                    error: error.message,
                    extensionVersion: version,
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
            // Quiet browsers wake only for an alarm; open extension views opt into live updates.
            startStatusMonitoring();
        }

        // Reuse a recent result for frequent background checks, such as Duo page polls.
        function recentStatus(maxAgeMs) {
            if (lastStatus && now() - lastStatusAt < maxAgeMs) return Promise.resolve(lastStatus);
            return refreshStatus();
        }

        return { refresh: refreshStatus, recent: recentStatus, start };
    },
};

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundStatus;
