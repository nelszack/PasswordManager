use crate::file::{key_file_path, new_key_file_path, read_bounded_file, sync_parent};
use crate::secret::SecretBuffer;
use crate::types::PasswordType;
use crate::vault::VaultCredentials;
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadInOut, Generate, KeyInit, Payload},
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
};
use zeroize::{Zeroize, Zeroizing};

const SALT_LEN: usize = 16;
const MAX_KEY_FILE_BYTES: u64 = 1024 * 1024;
const NONCE_LEN: usize = 24;
const VAULT_MAGIC: &[u8; 8] = b"PMVAULT\0";
const VAULT_VERSION: u8 = 1;
const KDF_KEYFILE: u8 = 0;
const KDF_ARGON2ID: u8 = 1;
const HEADER_LEN: usize = 8 + 1 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;
pub(crate) const ENCRYPTED_FILE_OVERHEAD: usize = HEADER_LEN + 16;

#[derive(Clone, Copy)]
pub(crate) struct KdfParameters {
    pub(crate) memory_kib: u32,
    pub(crate) iterations: u32,
    pub(crate) parallelism: u32,
}

pub(crate) const PRODUCTION_KDF_PARAMETERS: KdfParameters = KdfParameters {
    memory_kib: 64 * 1024,
    iterations: 3,
    parallelism: 1,
};

#[cfg(test)]
const FAST_TEST_KDF_PARAMETERS: KdfParameters = KdfParameters {
    memory_kib: 8 * 1024,
    iterations: 1,
    parallelism: 1,
};

#[cfg(test)]
thread_local! {
    static TEST_KDF_PARAMETERS: std::cell::Cell<KdfParameters> =
        const { std::cell::Cell::new(FAST_TEST_KDF_PARAMETERS) };
}

fn active_kdf_parameters() -> KdfParameters {
    #[cfg(test)]
    {
        TEST_KDF_PARAMETERS.get()
    }
    #[cfg(not(test))]
    {
        PRODUCTION_KDF_PARAMETERS
    }
}

#[cfg(test)]
pub(crate) fn with_test_kdf_parameters<T>(
    parameters: KdfParameters,
    operation: impl FnOnce() -> T,
) -> T {
    struct Restore(KdfParameters);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_KDF_PARAMETERS.set(self.0);
        }
    }

    let previous = TEST_KDF_PARAMETERS.replace(parameters);
    let _restore = Restore(previous);
    operation()
}

/// Shared policy for new vault credentials, including desktop form feedback.
pub fn validate_new_password(password: &str) -> Result<(), &'static str> {
    if password.chars().count() < 14 {
        return Err("master passwords must contain at least 14 characters");
    }
    if zxcvbn::zxcvbn(password, &[]).score() <= zxcvbn::Score::Two {
        return Err(
            "master password is too predictable; use a unique generated password or passphrase",
        );
    }
    Ok(())
}

pub fn try_prompt_for_confirmed_password(
    require_minimum: bool,
    retry: impl Fn(&str),
) -> Result<String, String> {
    loop {
        let mut p1 = Zeroizing::new(
            rpassword::prompt_password("Enter a password: ")
                .map_err(|error| format!("could not read password: {error}"))?,
        );
        let mut p2 = Zeroizing::new(
            rpassword::prompt_password("Re-enter the password: ")
                .map_err(|error| format!("could not read password confirmation: {error}"))?,
        );
        if require_minimum && let Err(error) = validate_new_password(&p1) {
            retry(&format!("{error}. Try again."));
        } else if p1 == p2 {
            p2.zeroize();
            return Ok(std::mem::take(&mut *p1));
        } else {
            retry("Passwords don't match. Try again.");
        }
        p1.zeroize();
        p2.zeroize();
    }
}

fn generate_key(path: &std::path::Path) -> Result<[u8; 32], String> {
    let key = Zeroizing::new(<[u8; 32]>::generate());
    let mut file = create_key_file(path)
        .map_err(|e| format!("could not create key file {}: {e}", path.display()))?;
    let result = protect_key_file(&file, path)
        .map_err(|e| format!("could not protect key file {}: {e}", path.display()))
        .and_then(|_| {
            file.write_all(&*key)
                .map_err(|e| format!("could not write key file {}: {e}", path.display()))
                .and_then(|_| {
                    file.sync_all()
                        .map_err(|e| format!("could not sync key file {}: {e}", path.display()))
                })
                .and_then(|_| {
                    sync_parent(path).map_err(|e| {
                        format!("could not sync key directory {}: {e}", path.display())
                    })
                })
        });
    // Windows writers deny delete sharing as well as read/write sharing.
    // Close before cleaning up an unsuccessful creation.
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(*key)
}

fn create_key_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Deny data access until the private ACL is installed and the writer
        // closes. Changing ACLs needs WRITE_DAC, not shared data access.
        options.share_mode(0);
    }
    options.open(path)
}

fn protect_key_file(file: &std::fs::File, _path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        crate::file::set_private_perms(_path)
    }
}

fn master_key_from_password_with_params(
    password: &str,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Option<[u8; 32]> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(32)).ok()?;
    run_cpu_intensive(|| {
        // Argon2's allocating API frees its working memory without wiping it.
        // Own the blocks so password-derived state is erased on every return path.
        let mut memory = Zeroizing::new(Vec::new());
        memory.try_reserve_exact(params.block_count()).ok()?;
        memory.resize(params.block_count(), Block::default());
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into_with_memory(password.as_bytes(), salt, &mut *key, &mut *memory)
            .ok()?;
        Some(*key)
    })
}

fn run_cpu_intensive<T>(operation: impl FnOnce() -> T) -> T {
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        tokio::task::block_in_place(operation)
    } else {
        operation()
    }
}

fn master_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let parameters = active_kdf_parameters();
    master_key_from_password_with_params(
        password,
        salt,
        parameters.memory_kib,
        parameters.iterations,
        parameters.parallelism,
    )
    .expect("the built-in Argon2 parameters are valid")
}
fn master_key_from_keyfile(keyfile_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(keyfile_bytes).as_bytes()
}
/// Master key from the key file at `key` (resolved under the data directory).
/// With `new`, a fresh random key file is created there first. Passwords are
/// derived only with a vault's own random salt; see [`encryption_master`].
pub fn try_keyfile_master_key(key: &str, new: bool) -> Result<[u8; 32], String> {
    if new {
        let file_path = new_key_file_path(key)?;
        let bytes = Zeroizing::new(generate_key(&file_path)?);
        Ok(master_key_from_keyfile(&*bytes))
    } else {
        let file_path = key_file_path(key)?;
        let bytes = read_bounded_file(&file_path, MAX_KEY_FILE_BYTES)
            .map_err(|e| format!("could not read key file {}: {e}", file_path.display()))?;
        Ok(master_key_from_keyfile(&bytes))
    }
}

fn encryption_key_from_master(master_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("vault-encryption-v1", master_key)
}

/// Mobile adapters supply key-file contents from the system document picker;
/// resolving desktop data paths would be invalid in an application sandbox.
pub(crate) fn credentials_from_keyfile_bytes(
    encrypted: &[u8],
    bytes: &[u8],
) -> Result<VaultCredentials, String> {
    let header = VaultHeader::parse(encrypted)?;
    if header.kdf != KDF_KEYFILE || bytes.is_empty() || bytes.len() > MAX_KEY_FILE_BYTES as usize {
        return Err("This vault does not accept the supplied key file".into());
    }
    let master = Zeroizing::new(master_key_from_keyfile(bytes));
    Ok(header.session(encryption_key_from_master(&master)))
}

/// New sandboxed vault/key change from document-picker key bytes; no filesystem path.
pub(crate) fn new_keyfile_credentials(bytes: &[u8]) -> Result<VaultCredentials, String> {
    if bytes.is_empty() || bytes.len() > MAX_KEY_FILE_BYTES as usize {
        return Err("Invalid key file size".into());
    }
    let master = Zeroizing::new(master_key_from_keyfile(bytes));
    let parameters = active_kdf_parameters();
    Ok(VaultCredentials::Session {
        encryption_key: encryption_key_from_master(&master),
        salt: <[u8; SALT_LEN]>::generate(),
        kdf: KDF_KEYFILE,
        memory_kib: parameters.memory_kib,
        iterations: parameters.iterations,
        parallelism: parameters.parallelism,
    })
}

/// Bind an already-derived key-file master key to this vault's header, so
/// unlocking does not read and hash the key file a second time. Returns
/// `None` when the vault is not protected by a key file.
pub(crate) fn keyfile_session(encrypted: &[u8], master: &[u8; 32]) -> Option<VaultCredentials> {
    let header = VaultHeader::parse(encrypted).ok()?;
    (header.kdf == KDF_KEYFILE).then(|| header.session(encryption_key_from_master(master)))
}

/// Whether this unlocked session came from a master password, so the person can
/// be re-verified with `password_matches`. Key-file sessions cannot.
pub(crate) fn password_session(credentials: &VaultCredentials) -> bool {
    matches!(credentials, VaultCredentials::Session { kdf, .. } if *kdf != KDF_KEYFILE)
}

/// Whether `password` derives this unlocked session's key: re-verifies the person
/// without reading or decrypting the vault. Key-file sessions never match.
pub(crate) fn password_matches(credentials: &VaultCredentials, password: &str) -> bool {
    let VaultCredentials::Session {
        encryption_key,
        salt,
        kdf,
        memory_kib,
        iterations,
        parallelism,
    } = credentials
    else {
        return false;
    };
    if *kdf == KDF_KEYFILE {
        return false;
    }
    let Some(master) = master_key_from_password_with_params(
        password,
        salt,
        *memory_kib,
        *iterations,
        *parallelism,
    ) else {
        return false;
    };
    let mut master = Zeroizing::new(master);
    let derived = Zeroizing::new(encryption_key_from_master(&master));
    master.zeroize();
    subtle::ConstantTimeEq::ct_eq(&derived[..], &encryption_key[..]).into()
}

pub(crate) fn cached_credentials(
    encrypted: &[u8],
    encryption_key: [u8; 32],
) -> Result<VaultCredentials, String> {
    Ok(VaultHeader::parse(encrypted)?.session(encryption_key))
}

fn encryption_master(key_pass: &PasswordType, salt: &[u8]) -> Result<[u8; 32], String> {
    match key_pass {
        PasswordType::Password(pass) => Ok(master_key_from_password(pass, salt)),
        PasswordType::Key(key) => try_keyfile_master_key(key, false),
    }
}

#[cfg(test)]
pub fn try_encrypt_file(
    key_pass: &mut VaultCredentials,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    try_encrypt_file_in_place(key_pass, plaintext.to_vec())
}

pub fn try_encrypt_file_in_place(
    key_pass: &mut VaultCredentials,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let mut plaintext = Zeroizing::new(plaintext);
    let len = plaintext.len();
    if plaintext.capacity() - len >= ENCRYPTED_FILE_OVERHEAD {
        // Frame within the caller's allocation: no copy or reallocation.
        plaintext.resize(len + HEADER_LEN, 0);
        plaintext.copy_within(..len, HEADER_LEN);
        return try_encrypt_framed(key_pass, SecretBuffer::from(plaintext));
    }
    let mut framed = framed_plaintext(len);
    framed.extend_from_slice(&plaintext);
    drop(plaintext);
    try_encrypt_framed(key_pass, framed)
}

/// A plaintext buffer with the vault header reserved in front and room for
/// `payload_capacity` bytes plus the tag, so encryption neither moves nor
/// reallocates the serialized document.
pub(crate) fn framed_plaintext(payload_capacity: usize) -> SecretBuffer {
    let mut framed =
        SecretBuffer::with_capacity(payload_capacity.saturating_add(ENCRYPTED_FILE_OVERHEAD));
    framed.extend_from_slice(&[0; HEADER_LEN]);
    framed
}

/// The serialized payload length of a buffer from [`framed_plaintext`].
pub(crate) fn framed_payload_len(framed: &SecretBuffer) -> usize {
    framed.len().saturating_sub(HEADER_LEN)
}

/// Encrypt a [`framed_plaintext`] buffer in place, then fill in its header.
pub(crate) fn try_encrypt_framed(
    key_pass: &mut VaultCredentials,
    mut framed: SecretBuffer,
) -> Result<Vec<u8>, String> {
    if framed.len() < HEADER_LEN {
        return Err("encryption failure".to_string());
    }
    let cached = match key_pass {
        VaultCredentials::Session {
            encryption_key,
            salt,
            kdf,
            memory_kib,
            iterations,
            parallelism,
        } => Some((
            Zeroizing::new(*encryption_key),
            *salt,
            *kdf,
            KdfParameters {
                memory_kib: *memory_kib,
                iterations: *iterations,
                parallelism: *parallelism,
            },
        )),
        _ => None,
    };
    let parameters = cached
        .as_ref()
        .map(|(_, _, _, parameters)| *parameters)
        .unwrap_or_else(active_kdf_parameters);
    let salt = cached
        .as_ref()
        .map_or_else(<[u8; SALT_LEN]>::generate, |(_, salt, _, _)| *salt);
    let kdf = match cached.as_ref() {
        Some((_, _, kdf, _)) => *kdf,
        None => match key_pass.supplied()? {
            PasswordType::Password(_) => KDF_ARGON2ID,
            PasswordType::Key(_) => KDF_KEYFILE,
        },
    };
    let mut enc_key = if let Some((key, _, _, _)) = cached.as_ref() {
        **key
    } else {
        let mut master_key = encryption_master(key_pass.supplied()?, &salt)?;
        let key = encryption_key_from_master(&master_key);
        master_key.zeroize();
        key
    };
    let mut session_key = Zeroizing::new(enc_key);
    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    enc_key.zeroize();
    let nonce = XNonce::generate();
    let mut header = [0u8; HEADER_LEN];
    header[..8].copy_from_slice(VAULT_MAGIC);
    header[8] = VAULT_VERSION;
    header[9] = kdf;
    header[10..14].copy_from_slice(&parameters.memory_kib.to_be_bytes());
    header[14..18].copy_from_slice(&parameters.iterations.to_be_bytes());
    header[18..22].copy_from_slice(&parameters.parallelism.to_be_bytes());
    header[22..22 + SALT_LEN].copy_from_slice(&salt);
    header[22 + SALT_LEN..HEADER_LEN].copy_from_slice(&nonce);
    // Reserve the tag while the buffer still holds plaintext; growth wipes.
    framed.reserve(ENCRYPTED_FILE_OVERHEAD - HEADER_LEN);
    let Ok(tag) =
        cipher.encrypt_inout_detached(&nonce, &header, (&mut framed[HEADER_LEN..]).into())
    else {
        session_key.zeroize();
        return Err("encryption failure".to_string());
    };
    framed[..HEADER_LEN].copy_from_slice(&header);
    framed.extend_from_slice(&tag);
    if !matches!(key_pass, VaultCredentials::Session { .. }) {
        *key_pass = VaultCredentials::Session {
            encryption_key: *session_key,
            salt,
            kdf,
            memory_kib: parameters.memory_kib,
            iterations: parameters.iterations,
            parallelism: parameters.parallelism,
        };
    }
    session_key.zeroize();
    Ok(std::mem::take(&mut *framed.into_inner()))
}

#[cfg(test)]
pub fn encrypt_file(key_pass: &mut VaultCredentials, plaintext: &[u8]) -> Vec<u8> {
    try_encrypt_file(key_pass, plaintext).expect("could not encrypt vault")
}

/// The authenticated vault header: magic, version, KDF parameters, salt, and
/// nonce, followed by the ciphertext and tag. Parsing validates untrusted
/// metadata without running the password KDF.
struct VaultHeader<'a> {
    kdf: u8,
    parameters: KdfParameters,
    salt: [u8; SALT_LEN],
    nonce: XNonce,
    /// The complete header, authenticated as associated data.
    header: &'a [u8],
    ciphertext: &'a [u8],
}
impl<'a> VaultHeader<'a> {
    fn parse(encrypted: &'a [u8]) -> Result<Self, &'static str> {
        if encrypted.len() < HEADER_LEN + 16 || !encrypted.starts_with(VAULT_MAGIC) {
            return Err("invalid or truncated encrypted vault header");
        }
        if encrypted[8] != VAULT_VERSION {
            return Err("unsupported encrypted vault version");
        }
        let (header, ciphertext) = encrypted.split_at(HEADER_LEN);
        let word = |at: usize| {
            u32::from_be_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]])
        };
        let parameters = KdfParameters {
            memory_kib: word(10),
            iterations: word(14),
            parallelism: word(18),
        };
        let kdf = header[9];
        if !matches!(kdf, KDF_KEYFILE | KDF_ARGON2ID)
            || !(8 * 1024..=1024 * 1024).contains(&parameters.memory_kib)
            || !(1..=10).contains(&parameters.iterations)
            || !(1..=16).contains(&parameters.parallelism)
        {
            return Err("unsupported or unsafe vault KDF parameters");
        }
        let (salt, nonce) = header[22..].split_at(SALT_LEN);
        Ok(Self {
            kdf,
            parameters,
            salt: salt.try_into().map_err(|_| "invalid vault salt")?,
            nonce: XNonce::try_from(nonce).map_err(|_| "invalid vault nonce")?,
            header,
            ciphertext,
        })
    }
    /// Cached credentials binding `encryption_key` to this header.
    fn session(&self, encryption_key: [u8; 32]) -> VaultCredentials {
        VaultCredentials::Session {
            encryption_key,
            salt: self.salt,
            kdf: self.kdf,
            memory_kib: self.parameters.memory_kib,
            iterations: self.parameters.iterations,
            parallelism: self.parameters.parallelism,
        }
    }
    /// Whether cached credentials were derived for exactly this header.
    fn matches(&self, credentials: &VaultCredentials) -> Option<Zeroizing<[u8; 32]>> {
        match credentials {
            VaultCredentials::Session {
                encryption_key,
                salt,
                kdf,
                memory_kib,
                iterations,
                parallelism,
            } if *salt == self.salt
                && *kdf == self.kdf
                && *memory_kib == self.parameters.memory_kib
                && *iterations == self.parameters.iterations
                && *parallelism == self.parameters.parallelism =>
            {
                Some(Zeroizing::new(*encryption_key))
            }
            _ => None,
        }
    }
}

/// Inspect untrusted format metadata without running the password KDF.
pub fn validate_vault_header(encrypted: &[u8]) -> Result<(), &'static str> {
    VaultHeader::parse(encrypted).map(|_| ())
}

pub fn decrypt_file(
    key_pass: &mut VaultCredentials,
    encrypted: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let header = VaultHeader::parse(encrypted).ok()?;
    let cached_key = header.matches(key_pass);
    let mut enc_key = if let Some(key) = cached_key.as_ref() {
        **key
    } else {
        let mut master = match (&*key_pass, header.kdf) {
            (VaultCredentials::Unlock(PasswordType::Password(password)), KDF_ARGON2ID) => {
                master_key_from_password_with_params(
                    password,
                    &header.salt,
                    header.parameters.memory_kib,
                    header.parameters.iterations,
                    header.parameters.parallelism,
                )?
            }
            (VaultCredentials::Unlock(PasswordType::Key(key)), KDF_KEYFILE) => {
                try_keyfile_master_key(key, false).ok()?
            }
            _ => return None,
        };
        let key = encryption_key_from_master(&master);
        master.zeroize();
        key
    };
    let session_key = Zeroizing::new(enc_key);
    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    enc_key.zeroize();
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &header.nonce,
                Payload {
                    msg: header.ciphertext,
                    aad: header.header,
                },
            )
            .ok()?,
    );
    if !matches!(key_pass, VaultCredentials::Session { .. }) {
        *key_pass = header.session(*session_key);
    }
    Some(plaintext)
}

#[cfg(test)]
#[path = "encryption_tests.rs"]
mod test;
