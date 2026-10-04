#[allow(dead_code)]
#[path = "src/cli.rs"]
mod cli;
#[allow(dead_code)]
#[path = "src/types.rs"]
mod types;

use clap::CommandFactory;
use clap_complete::{Shell, generate};
use directories::{BaseDirs, ProjectDirs};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

fn write_changed(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if fs::read(path).ok().as_deref() == Some(bytes) {
        return Ok(());
    }
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(path, bytes)
}

fn refresh_completions(profile: &Path, base: &BaseDirs) -> io::Result<()> {
    let shell = env::var("PM_COMPLETION_SHELL").unwrap_or_else(|_| {
        if cfg!(windows) {
            "powershell".into()
        } else {
            env::var("SHELL")
                .ok()
                .and_then(|s| {
                    Path::new(&s)
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                })
                .unwrap_or_else(|| "bash".into())
        }
    });
    let shell: Shell = shell.parse().map_err(|_| {
        io::Error::other(
            "unsupported PM_COMPLETION_SHELL; use bash, zsh, fish, elvish, or powershell",
        )
    })?;
    let output = env::var_os("PM_COMPLETION_OUTPUT")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| match shell {
            Shell::Bash => base.data_dir().join("bash-completion/completions/pm"),
            Shell::Zsh => base.home_dir().join(".zfunc/_pm"),
            Shell::Fish => base.config_dir().join("fish/completions/pm.fish"),
            Shell::Elvish => base.config_dir().join("elvish/lib/pm.elv"),
            _ => profile.join("completions/pm.ps1"),
        });
    let mut bytes = Vec::new();
    generate(shell, &mut cli::Cli::command(), "pm", &mut bytes);
    println!("cargo:rerun-if-changed={}", output.display());
    write_changed(&output, &bytes)?;
    Ok(())
}

fn refresh_host(profile: &Path) -> io::Result<()> {
    let data = env::var_os("PM_DATA_DIR")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            ProjectDirs::from("com", "myproject", "password_manager")
                .map(|dirs| dirs.data_dir().to_owned())
        })
        .ok_or_else(|| io::Error::other("could not locate application data directory"))?;
    let host = data.join("native-messaging").join(if cfg!(windows) {
        "pm-native-host.exe"
    } else {
        "pm-native-host"
    });
    if let Some(parent) = host.parent().filter(|parent| parent.is_dir()) {
        println!("cargo:rerun-if-changed={}", parent.display());
    }
    // Only refresh existing registrations; never guess a browser or extension ID.
    if fs::symlink_metadata(&host).is_err() {
        return Ok(());
    }
    let binary = profile.join(if cfg!(windows) { "pm.exe" } else { "pm" });
    refresh_host_platform(&host, &binary)
}

#[cfg(unix)]
fn refresh_host_platform(host: &Path, binary: &Path) -> io::Result<()> {
    use std::os::unix::fs::symlink;
    if !fs::symlink_metadata(host)?.file_type().is_symlink() {
        return Err(io::Error::other(format!(
            "refusing to replace non-symlink host {}",
            host.display()
        )));
    }
    if fs::read_link(host)? == binary {
        return Ok(());
    }
    let staged = host.with_extension(format!("update-{}", std::process::id()));
    symlink(binary, &staged)?;
    let result = fs::rename(&staged, host);
    if result.is_err() {
        let _ = fs::remove_file(staged);
    }
    result
}

#[cfg(windows)]
fn refresh_host_platform(host: &Path, binary: &Path) -> io::Result<()> {
    use std::process::Command;
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    // Cargo runs this hook before linking pm. A launcher avoids copying the old
    // executable and always starts the binary produced by the current build.
    let source = format!(
        r#"fn main() {{
        match std::process::Command::new({:?}).args(["native-host", "run"]).status() {{
            Ok(status) => std::process::exit(status.code().unwrap_or(1)),
            Err(error) => {{ eprintln!("Could not launch pm: {{error}}"); std::process::exit(1); }}
        }}
    }}"#,
        binary.to_string_lossy()
    );
    let source_path = out.join("native_launcher.rs");
    let launcher = out.join("pm-native-host.exe");
    if fs::read_to_string(&source_path).ok().as_deref() != Some(&source) || !launcher.exists() {
        fs::write(&source_path, source)?;
        let status = Command::new(env::var_os("RUSTC").unwrap())
            .arg(&source_path)
            .args([
                "--crate-name",
                "pm_native_launcher",
                "--edition=2024",
                "-O",
                "-o",
            ])
            .arg(&launcher)
            .status()?;
        if !status.success() {
            return Err(io::Error::other("could not compile native-host launcher"));
        }
    }
    let bytes = fs::read(launcher)?;
    if fs::read(host).ok().as_deref() == Some(&bytes) {
        return Ok(());
    }
    let staged = host.with_extension(format!("update-{}", std::process::id()));
    fs::write(&staged, bytes)?;
    let result = fs::rename(&staged, host);
    if result.is_err() {
        let _ = fs::remove_file(staged);
    }
    result.map_err(|error| io::Error::new(error.kind(), format!("{error}; fully close the browser, then rerun cargo build to refresh the native host")))
}

fn main() {
    for file in ["build.rs", "src"] {
        println!("cargo:rerun-if-changed={file}");
    }
    for name in [
        "PM_SKIP_BUILD_UPDATES",
        "PM_COMPLETION_SHELL",
        "PM_COMPLETION_OUTPUT",
        "PM_DATA_DIR",
        "SHELL",
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "APPDATA",
        "CI",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if env::var_os("PM_SKIP_BUILD_UPDATES").is_some()
        || env::var_os("CI").is_some()
        || env::var("HOST") != env::var("TARGET")
    {
        return;
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let profile = out.ancestors().nth(3).expect("Cargo profile directory");
    if let Some(base) = BaseDirs::new()
        && let Err(error) = refresh_completions(profile, &base)
    {
        println!("cargo:warning=Could not refresh shell completions: {error}");
    }
    if let Err(error) = refresh_host(profile) {
        // A missing tracked file keeps Cargo retrying a blocked update, even
        // when no project source changed between builds.
        println!(
            "cargo:rerun-if-changed={}",
            out.join("native-update-pending").display()
        );
        println!("cargo:warning=Could not refresh native host: {error}");
    }
}
