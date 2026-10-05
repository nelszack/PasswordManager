use super::*;
use block2::RcBlock;
use objc2_app_kit::{
    NSWorkspace, NSWorkspaceDidWakeNotification, NSWorkspaceSessionDidResignActiveNotification,
    NSWorkspaceWillSleepNotification,
};
use objc2_foundation::{
    NSDate, NSDistributedNotificationCenter, NSNotification, NSRunLoop, NSString,
};

pub(super) fn start(watch: Watch) {
    std::thread::spawn(move || {
        let workspace = NSWorkspace::sharedWorkspace();
        let center = workspace.notificationCenter();
        let distributed = NSDistributedNotificationCenter::defaultCenter();
        let callback_watch = watch.clone();
        let block = RcBlock::new(move |_notification: std::ptr::NonNull<NSNotification>| {
            let _ =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| callback_watch.lock()));
        });
        let locked = NSString::from_str("com.apple.screenIsLocked");
        // Observer tokens and block stay alive through removal. A dedicated
        // run loop delivers notifications without involving the CLI UI thread.
        unsafe {
            let observers = [
                NSWorkspaceWillSleepNotification,
                NSWorkspaceDidWakeNotification,
                NSWorkspaceSessionDidResignActiveNotification,
            ]
            .map(|name| {
                center.addObserverForName_object_queue_usingBlock(Some(name), None, None, &block)
            });
            let lock_observer = distributed.addObserverForName_object_queue_usingBlock(
                Some(&locked),
                None,
                None,
                &block,
            );
            watch.ready("macOS");
            let run_loop = NSRunLoop::currentRunLoop();
            while !watch.stopped() {
                objc2::rc::autoreleasepool(|_| {
                    run_loop.runUntilDate(&NSDate::dateWithTimeIntervalSinceNow(0.5))
                });
            }
            for observer in &observers {
                center.removeObserver(AsRef::<objc2::runtime::AnyObject>::as_ref(&**observer));
            }
            distributed.removeObserver(AsRef::<objc2::runtime::AnyObject>::as_ref(&*lock_observer));
        }
    });
}
