use super::*;
use std::ptr::null;
use windows_sys::Win32::{
    Foundation::*,
    System::{LibraryLoader::GetModuleHandleW, RemoteDesktop::*},
    UI::WindowsAndMessaging::*,
};

unsafe extern "system" fn procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // The boxed Watch remains alive until after DestroyWindow, including all
    // callbacks during window creation/destruction, on this single OS thread.
    unsafe {
        if message == WM_NCCREATE {
            let creation = &*(lparam as *const CREATESTRUCTW);
            SetWindowLongPtrW(window, GWLP_USERDATA, creation.lpCreateParams as isize);
        }
        let pointer = GetWindowLongPtrW(window, GWLP_USERDATA) as *const Watch;
        if let Some(watch) = pointer.as_ref() {
            if (message == WM_WTSSESSION_CHANGE
                && matches!(
                    wparam as u32,
                    WTS_SESSION_LOCK
                        | WTS_SESSION_LOGOFF
                        | WTS_CONSOLE_DISCONNECT
                        | WTS_REMOTE_DISCONNECT
                ))
                || (message == WM_POWERBROADCAST
                    && matches!(wparam as u32, PBT_APMSUSPEND | PBT_APMRESUMEAUTOMATIC))
            {
                // Never unwind across a system callback.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| watch.lock()));
            }
            if message == WM_TIMER && watch.stopped() {
                WTSUnRegisterSessionNotification(window);
                DestroyWindow(window);
                return 0;
            }
        }
        if message == WM_DESTROY {
            PostQuitMessage(0);
            return 0;
        }
        DefWindowProcW(window, message, wparam, lparam)
    }
}

pub(super) fn start(watch: Watch) {
    std::thread::spawn(move || {
        let watch = Box::new(watch);
        // A hidden top-level window receives power broadcasts; a message-only
        // window would not receive them. No UI is shown or user state changed.
        unsafe {
            let name: Vec<u16> = "PasswordManagerSystemLock\0".encode_utf16().collect();
            let instance = GetModuleHandleW(null());
            let class = WNDCLASSW {
                lpfnWndProc: Some(procedure),
                hInstance: instance,
                lpszClassName: name.as_ptr(),
                ..std::mem::zeroed()
            };
            if RegisterClassW(&class) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS {
                watch.warning("Windows", std::io::Error::last_os_error());
                return;
            }
            let window = CreateWindowExW(
                0,
                name.as_ptr(),
                name.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                null_mut(),
                null_mut(),
                instance,
                (&*watch as *const Watch).cast(),
            );
            if window.is_null() {
                watch.warning("Windows", std::io::Error::last_os_error());
                return;
            }
            let registered = WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION) != 0;
            if !registered {
                watch.warning("Windows session", std::io::Error::last_os_error());
            }
            if SetTimer(window, 1, 500, None) == 0 {
                watch.warning("Windows", std::io::Error::last_os_error());
            } else {
                watch.ready("Windows");
            }
            let mut message: MSG = std::mem::zeroed();
            loop {
                let result = GetMessageW(&mut message, null_mut(), 0, 0);
                if result <= 0 {
                    if result < 0 {
                        watch.warning("Windows", std::io::Error::last_os_error());
                    }
                    break;
                }
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
            if registered && IsWindow(window) != 0 {
                WTSUnRegisterSessionNotification(window);
            }
            if IsWindow(window) != 0 {
                DestroyWindow(window);
            }
        }
    });
}

fn null_mut<T>() -> *mut T {
    std::ptr::null_mut()
}
