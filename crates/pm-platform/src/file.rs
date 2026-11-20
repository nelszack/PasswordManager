use directories::ProjectDirs;
use std::{
    env, fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::OnceLock,
};
use zeroize::Zeroizing;

/// Check the opened file and bound the actual read, even if it grows after
/// metadata inspection. Returned and partial buffers are zeroized on drop.
pub fn read_bounded_file(path: &Path, max_bytes: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    fn validate(metadata: &fs::Metadata, max_bytes: u64) -> io::Result<()> {
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a regular file",
            ));
        }
        if metadata.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("file exceeds the {max_bytes} byte limit"),
            ));
        }
        Ok(())
    }
    validate(&fs::metadata(path)?, max_bytes)?;
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    validate(&metadata, max_bytes)?;
    // Size the buffer from the opened file. Growing a Vec frees the previous
    // allocation without wiping it, which matters for key and vault files.
    let expected = usize::try_from(metadata.len()).unwrap_or(0);
    read_bounded_with_capacity(file, max_bytes, expected)
}

/// Resolve a client-side path without opening it or requiring it to exist.
/// Empty-input policy and user-facing context belong to the caller.
pub fn absolute_unicode_path(path: impl AsRef<Path>) -> io::Result<String> {
    std::path::absolute(path)?
        .into_os_string()
        .into_string()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "file path must contain valid Unicode",
            )
        })
}

#[cfg(test)]
fn read_bounded(reader: impl Read, max_bytes: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    read_bounded_with_capacity(reader, max_bytes, 0)
}

fn read_bounded_with_capacity(
    reader: impl Read,
    max_bytes: u64,
    capacity: usize,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut contents = Zeroizing::new(Vec::with_capacity(capacity));
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut contents)?;
    if contents.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds the {max_bytes} byte limit"),
        ));
    }
    Ok(contents)
}

#[cfg(target_os = "windows")]
pub const WINDOWS_CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(target_os = "windows")]
pub fn hidden_windows_command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    use std::os::windows::process::CommandExt;

    let mut command = std::process::Command::new(program);
    command.creation_flags(WINDOWS_CREATE_NO_WINDOW);
    command
}

pub const TOKEN_FILE: &str = "session.key";
pub const SERVER_LOCK_FILE: &str = "server.lock";
#[cfg(target_os = "windows")]
pub const SERVER_PID_FILE: &str = "server.pid";
pub const CONFIG_DIR_ENV: &str = "PM_CONFIG_DIR";
pub const DATA_DIR_ENV: &str = "PM_DATA_DIR";

#[cfg(unix)]
pub fn set_private_perms(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(unix)]
pub fn set_private_dir_perms(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
#[cfg(not(target_os = "windows"))]
pub fn set_private_perms(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
#[cfg(not(target_os = "windows"))]
pub fn set_private_dir_perms(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Replaces the DACL of `path` with a protected one granting full control to
/// the current user only, so inherited grants and explicit grants to other
/// principals are both removed, then reads it back and verifies it.
/// Directories' single ACE is inherited by new children (container and object
/// inherit, no propagation limits).
#[cfg(target_os = "windows")]
fn set_windows_acl(path: &Path, directory: bool) -> std::io::Result<()> {
    windows_acl::protect(path, directory).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("could not protect ACL for {}: {error}", path.display()),
        )
    })
}

#[cfg(target_os = "windows")]
mod windows_acl {
    use std::{io, os::windows::ffi::OsStrExt, path::Path, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree},
        Security::{
            ACCESS_ALLOWED_ACE, ACE_FLAGS, ACL, ACL_REVISION, ACL_SIZE_INFORMATION,
            AclSizeInformation, AddAccessAllowedAceEx,
            Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW},
            CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
            GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl,
            IsValidSid, OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::FILE_ALL_ACCESS,
        System::{
            SystemServices::ACCESS_ALLOWED_ACE_TYPE,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    };

    pub(super) fn protect(path: &Path, directory: bool) -> io::Result<()> {
        let mut name: Vec<u16> = std::path::absolute(path)?
            .as_os_str()
            .encode_wide()
            .collect();
        if name.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains a NUL character",
            ));
        }
        name.push(0);
        let user = CurrentUser::query()?;
        let flags = if directory {
            CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
        } else {
            0
        };
        let mut acl = single_ace_acl(user.sid(), flags)?;
        // SAFETY: `name` is NUL-terminated UTF-16 that outlives the call, and
        // `acl` is an initialized ACL buffer that outlives it. Null owner,
        // group, and SACL pointers are permitted because only the DACL is
        // selected by the security-information flags.
        let status = unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl.as_mut_ptr().cast::<ACL>(),
                ptr::null(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        verify(&name, user.sid(), flags)
    }

    /// The current process token's user SID, in an aligned owned buffer.
    struct CurrentUser(Vec<u64>);
    impl CurrentUser {
        fn query() -> io::Result<Self> {
            let mut token: HANDLE = ptr::null_mut();
            // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
            // closing; `token` is a valid out pointer.
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
                return Err(io::Error::last_os_error());
            }
            struct Token(HANDLE);
            impl Drop for Token {
                fn drop(&mut self) {
                    // SAFETY: the handle came from a successful
                    // OpenProcessToken and is closed exactly once.
                    unsafe { CloseHandle(self.0) };
                }
            }
            let token = Token(token);
            let mut length = 0u32;
            // SAFETY: a null buffer with zero length only asks for the
            // required size, which is written to `length`.
            unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut length) };
            if (length as usize) < size_of::<TOKEN_USER>() {
                return Err(io::Error::last_os_error());
            }
            // u64 storage satisfies TOKEN_USER's pointer alignment.
            let mut buffer = vec![0u64; (length as usize).div_ceil(size_of::<u64>())];
            // SAFETY: `buffer` is writable for at least `length` bytes and
            // suitably aligned; `length` receives the size actually used.
            if unsafe {
                GetTokenInformation(
                    token.0,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    length,
                    &mut length,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let user = Self(buffer);
            // SAFETY: the SID pointer refers into `user.0`, which the token
            // information call filled with a TOKEN_USER and its SID.
            if unsafe { IsValidSid(user.sid()) } == 0 {
                return Err(io::Error::other("current user SID is invalid"));
            }
            Ok(user)
        }
        /// Valid while `self` is alive; the SID is stored inside the buffer.
        fn sid(&self) -> PSID {
            // SAFETY: the buffer starts with an initialized, aligned TOKEN_USER.
            unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
        }
    }

    /// A DACL containing one full-control allow ACE for `sid`.
    fn single_ace_acl(sid: PSID, flags: ACE_FLAGS) -> io::Result<Vec<u32>> {
        // SAFETY: `sid` was validated with IsValidSid.
        let sid_length = unsafe { GetLengthSid(sid) } as usize;
        let size =
            size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid_length;
        let size = size.next_multiple_of(size_of::<u32>());
        let size_u32 = u32::try_from(size).map_err(|_| io::Error::other("ACL is too large"))?;
        // u32 storage gives the DWORD alignment an ACL requires.
        let mut acl = vec![0u32; size / size_of::<u32>()];
        // SAFETY: `acl` is writable for `size` bytes and DWORD aligned.
        if unsafe { InitializeAcl(acl.as_mut_ptr().cast(), size_u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `acl` was initialized above with room for exactly this ACE,
        // and `sid` is valid.
        if unsafe {
            AddAccessAllowedAceEx(
                acl.as_mut_ptr().cast(),
                ACL_REVISION,
                flags,
                FILE_ALL_ACCESS,
                sid,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(acl)
    }

    /// Reads the DACL back: it must be protected and contain exactly one
    /// explicit full-control allow ACE for `sid` with the requested flags.
    fn verify(name: &[u16], sid: PSID, flags: ACE_FLAGS) -> io::Result<()> {
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `name` is NUL-terminated; out pointers are valid. On
        // success, `descriptor` owns the memory `dacl` points into.
        let status = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        struct Descriptor(PSECURITY_DESCRIPTOR);
        impl Drop for Descriptor {
            fn drop(&mut self) {
                // SAFETY: allocated by GetNamedSecurityInfoW, freed once.
                unsafe { LocalFree(self.0) };
            }
        }
        let descriptor = Descriptor(descriptor);
        let failed = |reason: &str| {
            Err(io::Error::other(format!(
                "private ACL verification failed: {reason}"
            )))
        };
        let mut control = 0u16;
        let mut revision = 0u32;
        // SAFETY: the descriptor is valid until dropped; out pointers are valid.
        if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // A null DACL would grant everyone full access.
        if dacl.is_null() || control & SE_DACL_PROTECTED == 0 {
            return failed("DACL is missing or not protected");
        }
        let mut size = ACL_SIZE_INFORMATION::default();
        // SAFETY: `dacl` points into the live descriptor; `size` is a
        // correctly sized ACL_SIZE_INFORMATION.
        if unsafe {
            GetAclInformation(
                dacl,
                (&raw mut size).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if size.AceCount != 1 {
            return failed("unexpected access rules");
        }
        let mut ace: *mut core::ffi::c_void = ptr::null_mut();
        // SAFETY: index 0 exists (AceCount is 1); `ace` receives a pointer
        // into the live DACL.
        if unsafe { GetAce(dacl, 0, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: every ACE begins with an ACE_HEADER.
        let header = unsafe { *ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || u32::from(header.AceFlags) != flags
            || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
        {
            return failed("unexpected principal or rights");
        }
        let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
        // SAFETY: the header identifies an ACCESS_ALLOWED_ACE of sufficient
        // size; its SID begins at `SidStart` within the ACE.
        let (mask, ace_sid) = unsafe { ((*allowed).Mask, (&raw mut (*allowed).SidStart).cast()) };
        // SAFETY: both SIDs are valid for the duration of the call.
        if mask != FILE_ALL_ACCESS || unsafe { EqualSid(ace_sid, sid) } == 0 {
            return failed("unexpected principal or rights");
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
pub fn set_private_perms(path: &Path) -> std::io::Result<()> {
    set_windows_acl(path, false)
}

#[cfg(target_os = "windows")]
pub fn set_private_dir_perms(path: &Path) -> std::io::Result<()> {
    use std::{collections::HashSet, sync::Mutex};

    static PROTECTED_DIRS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    let protected = PROTECTED_DIRS.get_or_init(|| Mutex::new(HashSet::new()));
    let mut protected = protected
        .lock()
        .map_err(|_| std::io::Error::other("private-directory ACL cache is poisoned"))?;
    if protected.contains(path) {
        return Ok(());
    }
    set_windows_acl(path, true)?;
    protected.insert(path.to_path_buf());
    Ok(())
}

#[cfg(unix)]
pub fn sync_parent(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
pub fn sync_parent(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Whether the atomic installation may replace an existing destination.
#[derive(Clone, Copy, Debug)]
pub enum AtomicWriteMode {
    Replace,
    CreateNew,
}

#[derive(Debug)]
pub struct AtomicWriteError {
    pub phase: &'static str,
    pub source: io::Error,
    committed: bool,
}
impl AtomicWriteError {
    pub fn committed(&self) -> bool {
        self.committed
    }
}
impl std::fmt::Display for AtomicWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.committed {
            write!(f, "file saved but durability uncertain: {}", self.source)
        } else {
            write!(f, "could not {}: {}", self.phase, self.source)
        }
    }
}
impl std::error::Error for AtomicWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Install private bytes atomically. The caller owns parent creation and path policy.
/// A directory-sync failure is reported as committed so callers never retry blindly.
pub fn atomic_write_private(
    path: &Path,
    bytes: &[u8],
    mode: AtomicWriteMode,
) -> Result<(), AtomicWriteError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let before = |phase, source| AtomicWriteError {
        phase,
        source,
        committed: false,
    };
    let mut file = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| before("create private temporary file", e))?;
    set_private_perms(file.path()).map_err(|e| before("protect private temporary file", e))?;
    file.write_all(bytes)
        .map_err(|e| before("write private temporary file", e))?;
    file.as_file()
        .sync_all()
        .map_err(|e| before("sync private temporary file", e))?;
    match mode {
        AtomicWriteMode::Replace => file.persist(path),
        AtomicWriteMode::CreateNew => file.persist_noclobber(path),
    }
    .map_err(|e| before("install private file", e.error))?;
    sync_parent(path).map_err(|source| AtomicWriteError {
        phase: "sync parent directory",
        source,
        committed: true,
    })
}

/// Export and backup destinations must not replace application-owned files.
/// Resolve parent symlinks and existing destination symlinks before checking.
pub fn validate_external_output_path(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let candidate = fs::canonicalize(parent)?.join(path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination must name a file")
    })?);
    let existing = match fs::canonicalize(path) {
        Ok(path) => Some(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    for directory in [data_dir(), config_dir()] {
        let protected = match fs::canonicalize(directory) {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if candidate.starts_with(&protected)
            || existing
                .as_ref()
                .is_some_and(|path| path.starts_with(&protected))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "export and backup destinations must be outside application data and configuration directories",
            ));
        }
    }
    Ok(())
}

pub fn key_file_path(name: &str) -> Result<PathBuf, String> {
    let path = Path::new(name);
    if !path.is_absolute() {
        return Err("key file path must be absolute".to_string());
    }
    Ok(path.to_path_buf())
}

pub fn resolve_new_key_path(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("key file path cannot be empty".to_string());
    }
    let path = std::path::absolute(name)
        .map_err(|error| format!("could not resolve key file path: {error}"))?;
    path.into_os_string()
        .into_string()
        .map_err(|_| "key file path must contain valid Unicode".to_string())
}

pub fn resolve_key_path(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("key file path cannot be empty".to_string());
    }
    let path = Path::new(name);
    if path.is_absolute() {
        return Ok(name.to_string());
    }
    resolve_new_key_path(name)
}

pub fn new_key_file_path(name: &str) -> Result<PathBuf, String> {
    let path = Path::new(name);
    if !path.is_absolute() {
        return Err("new key file paths must be absolute and outside application data".to_string());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| "key file path has no parent directory".to_string())?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| format!("could not resolve key file directory: {error}"))?;
    let candidate = parent.join(
        path.file_name()
            .ok_or_else(|| "key file path must include a filename".to_string())?,
    );
    let application_data = fs::canonicalize(data_dir())
        .map_err(|error| format!("could not resolve application data directory: {error}"))?;
    if candidate.starts_with(&application_data) {
        return Err("new key files must be stored outside the application data directory".into());
    }
    Ok(candidate)
}

pub fn data_dir() -> PathBuf {
    let data_dir = TEST_DATA_DIR
        .get()
        .map(|d| d.path().to_path_buf())
        .unwrap_or_else(project_data_dir);
    if let Err(error) = fs::create_dir_all(&data_dir).and_then(|_| set_private_dir_perms(&data_dir))
    {
        eprintln!(
            "Error: could not initialize data directory {}: {error}",
            data_dir.display()
        );
        std::process::exit(1);
    }
    data_dir
}

pub fn config_dir() -> PathBuf {
    env::var_os(CONFIG_DIR_ENV)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(project_config_dir)
}

fn project_data_dir() -> PathBuf {
    if let Some(path) = env::var_os(DATA_DIR_ENV).filter(|path| !path.is_empty()) {
        return PathBuf::from(path);
    }
    let Some(proj_dir) = ProjectDirs::from("com", "myproject", "password_manager") else {
        eprintln!("Error: could not locate the application data directory.");
        std::process::exit(1);
    };
    proj_dir.data_dir().to_path_buf()
}

fn project_config_dir() -> PathBuf {
    let Some(proj_dir) = ProjectDirs::from("com", "myproject", "password_manager") else {
        eprintln!("Error: could not locate the application config directory.");
        std::process::exit(1);
    };
    proj_dir.config_dir().to_path_buf()
}

static TEST_DATA_DIR: OnceLock<&'static tempfile::TempDir> = OnceLock::new();

#[cfg(any(test, feature = "fixtures"))]
pub fn init_test_data_dir() {
    let _ = TEST_DATA_DIR.get_or_init(|| Box::leak(Box::new(tempfile::TempDir::new().unwrap())));
}

/// Discover opaque vault filenames without opening contents or following symlinks.
/// Callers decide whether a missing directory means an empty list or an error.
pub fn list_vault_files(directory: &std::path::Path) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.ends_with(".enc") && entry.file_type()?.is_file() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod test {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn absolute_unicode_paths_preserve_names_without_requiring_an_existing_file() {
        let root = TempDir::new().unwrap();
        let missing = root.path().join("École vault ☃.json");
        assert_eq!(
            absolute_unicode_path(&missing).unwrap(),
            missing.to_str().unwrap()
        );
        assert!(!missing.exists());
        let relative = absolute_unicode_path("École vault ☃.json").unwrap();
        assert!(Path::new(&relative).is_absolute());
        assert!(Path::new(&relative).ends_with("École vault ☃.json"));
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let invalid = root.path().join(std::ffi::OsString::from_vec(vec![0xff]));
            assert_eq!(
                absolute_unicode_path(invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn atomic_private_writes_respect_creation_replacement_and_failed_installation() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("private.bin");
        atomic_write_private(&path, b"original", AtomicWriteMode::CreateNew).unwrap();
        let error =
            atomic_write_private(&path, b"uncommitted", AtomicWriteMode::CreateNew).unwrap_err();
        assert!(!error.committed());
        assert_eq!(error.source.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"original");
        atomic_write_private(&path, b"replacement", AtomicWriteMode::Replace).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let directory = root.path().join("directory");
        fs::create_dir(&directory).unwrap();
        let error =
            atomic_write_private(&directory, b"uncommitted", AtomicWriteMode::Replace).unwrap_err();
        assert!(!error.committed());
        assert!(directory.is_dir());
        assert_eq!(
            fs::read_dir(root.path()).unwrap().count(),
            2,
            "failed installation must remove temporary files"
        );
        let missing = root.path().join("missing").join("private.bin");
        assert!(atomic_write_private(&missing, b"uncommitted", AtomicWriteMode::Replace).is_err());
        assert!(
            !missing.parent().unwrap().exists(),
            "parent creation is caller policy"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn private_windows_acls_remove_explicit_grants_to_other_principals() {
        let root = TempDir::new().unwrap();
        let directory = root.path().join("private directory");
        fs::create_dir(&directory).unwrap();
        let file = directory.join("private file.txt");
        fs::write(&file, b"synthetic-secret").unwrap();
        for (path, is_directory) in [(&directory, true), (&file, false)] {
            let output = hidden_windows_command("icacls.exe")
                .arg(path)
                .args(["/grant", "*S-1-1-0:(F)"])
                .output()
                .unwrap();
            assert!(output.status.success());
            // This includes read-back verification that only our SID remains.
            set_windows_acl(path, is_directory).unwrap();
            let output = hidden_windows_command("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", r#"
                    $ErrorActionPreference = 'Stop'
                    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                    if ($env:PM_TEST_ACL_DIRECTORY -eq '1') {
                        $acl = [System.IO.Directory]::GetAccessControl($env:PM_TEST_ACL_PATH)
                    } else {
                        $acl = [System.IO.File]::GetAccessControl($env:PM_TEST_ACL_PATH)
                    }
                    $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
                    if (-not $acl.AreAccessRulesProtected -or $rules.Count -ne 1 -or
                        $rules[0].IdentityReference.Value -ne $sid) { exit 1 }
                "#])
                .env("PM_TEST_ACL_PATH", path)
                .env("PM_TEST_ACL_DIRECTORY", if is_directory { "1" } else { "0" })
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn directory_sync_accepts_a_bare_filename() {
        sync_parent(Path::new("relative-export.json")).unwrap();
        sync_parent(Path::new("./relative-backup.pmbackup")).unwrap();
    }

    #[test]
    fn bounded_reads_validate_files_and_enforce_the_limit_on_actual_bytes() {
        for contents in [vec![], vec![7; 7], vec![7; 8]] {
            assert_eq!(&*read_bounded(contents.as_slice(), 8).unwrap(), &contents);
        }
        // Models bytes added after metadata was checked. Read at most one
        // extra byte to detect overflow, rather than buffering the whole input.
        let mut input = io::Cursor::new(vec![7; 64]);
        assert_eq!(
            read_bounded(&mut input, 8).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(input.position(), 9);

        let directory = TempDir::new().unwrap();
        let path = directory.path().join("input");
        fs::write(&path, b"12345678").unwrap();
        assert_eq!(&*read_bounded_file(&path, 8).unwrap(), b"12345678");
        assert_eq!(
            read_bounded_file(&path, 7).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_bounded_file(directory.path(), 8).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn new_key_files_require_an_external_absolute_path() {
        init_test_data_dir();
        let external = TempDir::new().unwrap();
        assert!(new_key_file_path(external.path().join("vault.key").to_str().unwrap()).is_ok());
        assert!(new_key_file_path("vault.key").is_err());
        assert!(new_key_file_path(data_dir().join("vault.key").to_str().unwrap()).is_err());
    }

    #[test]
    fn relative_key_paths_resolve_from_the_client_working_directory() {
        for (label, resolve) in [
            (
                "new key",
                resolve_new_key_path as fn(&str) -> Result<String, String>,
            ),
            (
                "existing key",
                resolve_key_path as fn(&str) -> Result<String, String>,
            ),
        ] {
            let resolved = resolve("keys/vault.key").unwrap();
            assert!(Path::new(&resolved).is_absolute(), "{label}");
            assert!(
                Path::new(&resolved).ends_with(Path::new("keys/vault.key")),
                "{label}"
            );
            assert!(
                Path::new(&resolve("vault.key").unwrap()).is_absolute(),
                "{label}"
            );
            assert!(resolve("").is_err(), "{label}");
        }
    }
}
