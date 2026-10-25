//! Desktop launchers point at the same executable used by the CLI and server.
use std::path::PathBuf;

/// Keep the console subsystem for CLI/native-host I/O, but release the console
/// Windows creates when the GUI executable is launched directly from Explorer.
#[cfg(all(feature = "desktop", target_os = "windows"))]
pub fn detach_private_console() {
    use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};

    let mut processes = [0_u32; 2];
    // The array is valid for the call. A count greater than its capacity means
    // other processes share the console; leave their terminal attached.
    let count = unsafe { GetConsoleProcessList(processes.as_mut_ptr(), processes.len() as u32) };
    if count == 1 && processes[0] == std::process::id() {
        // No other process uses this console, and GUI tasks use no console I/O.
        unsafe { FreeConsole() };
    }
}

pub fn install_shortcut() -> Result<PathBuf, String> {
    #[cfg(target_os = "linux")]
    {
        let executable = std::env::current_exe().map_err(|e| e.to_string())?;
        let base = directories::BaseDirs::new().ok_or("could not find user data directory")?;
        let applications = base.data_dir().join("applications");
        std::fs::create_dir_all(&applications).map_err(|e| e.to_string())?;
        let path = applications.join("com.passwordmanager.Pm.desktop");
        std::fs::write(&path, launcher(&executable)?).map_err(|e| e.to_string())?;
        Ok(path)
    }
    #[cfg(not(target_os = "linux"))]
    Err("Automatic shortcut installation is currently available on Linux. Create a shortcut to the pm executable with no arguments on this platform.".into())
}

#[cfg(target_os = "linux")]
fn launcher(executable: &std::path::Path) -> Result<String, String> {
    let path = executable
        .to_str()
        .ok_or("executable path is not valid UTF-8")?;
    if path.contains(['\n', '\r', '\0']) {
        return Err("executable path contains unsupported control characters".into());
    }
    // Desktop Entry Exec has its own quoting rules, then string-value escaping.
    // Percent must be doubled so a filename cannot introduce field codes.
    let mut quoted = String::new();
    for ch in path.chars() {
        match ch {
            '%' => quoted.push_str("%%"),
            '\\' | '"' | '`' | '$' => {
                quoted.push('\\');
                quoted.push(ch);
            }
            _ => quoted.push(ch),
        }
    }
    let quoted = quoted.replace('\\', "\\\\");
    Ok(format!(
        "[Desktop Entry]\nType=Application\nVersion=1.0\nName=Password Manager\nComment=Manage your encrypted local vault\nExec=\"{quoted}\"\nIcon=dialog-password\nTerminal=false\nCategories=Utility;Security;\nKeywords=password;vault;credentials;\nStartupWMClass=com.passwordmanager.Pm\n"
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn exec_quotes_paths_without_shell_expansion_or_field_code_injection() {
        let entry = launcher(std::path::Path::new("/tmp/a b/$HOME`x`%f/pm")).unwrap();
        assert!(entry.contains("Exec=\"/tmp/a b/\\\\$HOME\\\\`x\\\\`%%f/pm\"\n"));
        assert!(entry.contains("Terminal=false\n"));
        assert!(launcher(std::path::Path::new("/tmp/a\nExec=bad")).is_err());
    }
}
