//! Open only explicit web addresses, passed directly to the platform handler.
pub(super) fn address(value: &str) -> Result<String, &'static str> {
    if value.chars().any(char::is_control) {
        return Err("This website address contains invalid characters.");
    }
    let url = url::Url::parse(value.trim())
        .map_err(|_| "Enter a complete https:// or http:// website address.")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.host_str().is_some_and(|host| host.contains('*'))
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(
            "Open website supports http:// and https:// addresses without embedded credentials or wildcards.",
        );
    }
    Ok(url.into())
}

pub(super) fn open(value: &str) -> Result<(), String> {
    let address = address(value).map_err(str::to_owned)?;
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        let operation: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
        let address: Vec<u16> = std::ffi::OsStr::new(&address)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let result = unsafe {
            windows_sys::Win32::UI::Shell::ShellExecuteW(
                std::ptr::null_mut(),
                operation.as_ptr(),
                address.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
            )
        };
        if result as usize <= 32 {
            return Err("Could not open the default browser.".into());
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let launcher = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        let status = std::process::Command::new(launcher)
            .arg(address)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|_| "Could not open the default browser.")?;
        if !status.success() {
            return Err(
                "Could not open the default browser. Check your default browser setting.".into(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_web_addresses_can_reach_the_platform_handler() {
        for invalid in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https://*.example.com",
            "https://user:secret@example.com",
            "--help",
            "https://example.com\nother",
        ] {
            assert!(address(invalid).is_err(), "{invalid}");
        }
        assert_eq!(
            address("https://example.com/a?q=hello%20world"),
            Ok("https://example.com/a?q=hello%20world".into())
        );
    }
}
