//! OS event sources never carry credentials. A callback locks the existing
//! session synchronously, using the same cleanup path as explicit locking.
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

type Lock = Arc<dyn Fn() + Send + Sync>;

pub(super) struct Monitor {
    stopped: Arc<AtomicBool>,
    warnings: Arc<Mutex<BTreeMap<&'static str, String>>>,
}

#[derive(Clone)]
struct Watch {
    stopped: Arc<AtomicBool>,
    warnings: Arc<Mutex<BTreeMap<&'static str, String>>>,
    lock: Lock,
}

impl Watch {
    fn lock(&self) {
        if !self.stopped.load(Ordering::Acquire) {
            (self.lock)();
        }
    }
    fn warning(&self, source: &'static str, error: impl std::fmt::Display) {
        self.warnings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                source,
                format!("System lock monitoring ({source}): {error}"),
            );
    }
    fn ready(&self, source: &'static str) {
        self.warnings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(source);
    }
    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
}

impl Monitor {
    pub(super) fn start(lock: Lock) -> Arc<Self> {
        let monitor = Arc::new(Self {
            stopped: Arc::new(AtomicBool::new(false)),
            warnings: Arc::new(Mutex::new(BTreeMap::new())),
        });
        let watch = Watch {
            stopped: monitor.stopped.clone(),
            warnings: monitor.warnings.clone(),
            lock,
        };
        platform_start(watch);
        monitor
    }
    pub(super) fn warning(&self) -> Option<String> {
        let warnings = self.warnings.lock().unwrap_or_else(|e| e.into_inner());
        (!warnings.is_empty()).then(|| warnings.values().cloned().collect::<Vec<_>>().join("; "))
    }
    pub(super) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

fn platform_start(watch: Watch) {
    #[cfg(target_os = "linux")]
    linux::start(watch);
    #[cfg(target_os = "windows")]
    windows::start(watch);
    #[cfg(target_os = "macos")]
    macos::start(watch);
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    watch.warning(
        "platform",
        "screen-lock/suspend notifications are unsupported on this OS",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stopped_watch_cannot_lock_a_later_session_and_warnings_are_retained() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = calls.clone();
        let monitor = Monitor {
            stopped: Arc::new(AtomicBool::new(false)),
            warnings: Arc::new(Mutex::new(BTreeMap::new())),
        };
        let watch = Watch {
            stopped: monitor.stopped.clone(),
            warnings: monitor.warnings.clone(),
            lock: Arc::new(move || {
                count.fetch_add(1, Ordering::Relaxed);
            }),
        };
        watch.lock();
        watch.warning("test", "unavailable");
        assert!(monitor.warning().unwrap().contains("unavailable"));
        monitor.stop();
        watch.lock();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        watch.ready("test");
        assert!(monitor.warning().is_none());
    }
}
