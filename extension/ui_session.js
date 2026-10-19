"use strict";
// Views own their live-status lease. Reconnection also wakes a restarted worker,
// whose startup gate invalidates orphan decisions before accepting new work.
(() => {
    let lease, disposed = false, timer;
    function connect() {
        if (disposed) return;
        try {
            lease = chrome.runtime.connect({ name: "pm-ui" });
            lease.onDisconnect.addListener(() => {
                window.dispatchEvent(new Event("pm-worker-disconnected"));
                if (!disposed) timer = setTimeout(connect, 250);
            });
        } catch (_) { window.dispatchEvent(new Event("pm-worker-disconnected")); }
    }
    window.addEventListener("pagehide", () => { disposed = true; clearTimeout(timer); lease?.disconnect(); }, { once: true });
    connect();
})();
