// Own state per worker instance; browser services are supplied by background.js.
const PasswordManagerBackgroundStatus = {
    create({
        chrome,
        nativeRequest,
        // Pushed status while extension views are open; polling is the fallback.
        subscribeStatus = null,
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
        // A subscription that delivers nothing (an older native host, or the
        // server's subscriber limit) is retried only this often.
        const EVENTS_RETRY_MS = 30_000;
        let cachedStatus = null;
        let lastStatus = null;
        let lastStatusAt = -Infinity;
        let statusRefresh = null;
        let liveTimer = null;
        let subscription = null;
        let retryEventsAt = -Infinity;
        let pollSawRunning = false;
        // Counts pushed records, so a poll already in flight cannot replace newer pushed status.
        let pushes = 0;
        const views = new Set();
        chrome.runtime.onConnect?.addListener(port => {
            if (port.name !== "pm-ui") return;
            views.add(port);
            refreshStatus();
            startLive();
            port.onDisconnect.addListener(() => {
                views.delete(port);
                if (!views.size) {
                    stopPolling();
                    subscription?.close();
                    subscription = null;
                    closeIdle();
                }
            });
        });

        function startPolling() {
            if (liveTimer === null) liveTimer = setInterval(poll, LIVE_STATUS_POLL_MS);
        }

        function stopPolling() {
            clearInterval(liveTimer);
            liveTimer = null;
        }

        // Open views follow pushed status; each change arrives as it happens
        // instead of within the next poll, and an idle vault costs no requests.
        function startLive() {
            if (!views.size || subscription) return;
            if (!subscribeStatus || now() < retryEventsAt) {
                startPolling();
                return;
            }
            stopPolling();
            subscription = subscribeStatus({
                onStatus: response => {
                    pushes++;
                    try {
                        publishStatus(statusFrom(response));
                    } catch (_) {
                        refreshStatus();
                    }
                },
                onEnd: ({ received }) => {
                    subscription = null;
                    if (!received) retryEventsAt = now() + EVENTS_RETRY_MS;
                    if (!views.size) return;
                    // The server may have stopped: show that now, then poll until it returns.
                    // Only a later not-running to running change resets the retry delay.
                    pollSawRunning = Boolean(lastStatus?.running);
                    refreshStatus();
                    startPolling();
                },
            });
        }

        function poll() {
            refreshStatus().then(status => {
                if (!status.running) {
                    pollSawRunning = false;
                    return;
                }
                // A server that just started gets a fresh subscription attempt.
                if (!pollSawRunning) retryEventsAt = -Infinity;
                pollSawRunning = true;
                if (!status.versionError && subscribeStatus && now() >= retryEventsAt) startLive();
            });
        }
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

        // A successful status response, polled or pushed.
        function statusFrom(response) {
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
                return statusFrom(response);
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
            const pushesBefore = pushes;
            statusRefresh = serverStatus()
                .then(status => {
                    if (pushes === pushesBefore) publishStatus(status);
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

module.exports = PasswordManagerBackgroundStatus;
