use crate::file::{key_file_path, new_key_file_path, set_private_perms, sync_parent};
use crate::types::PasswordType;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadInOut, Generate, KeyInit, Payload},
};
use std::{
    fs::{self, OpenOptions, read},
    io::Write,
};
use zeroize::Zeroize;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const VAULT_MAGIC: &[u8; 8] = b"PMVAULT\0";
const VAULT_VERSION: u8 = 1;
const KDF_KEYFILE: u8 = 0;
const KDF_ARGON2ID: u8 = 1;
const HEADER_LEN: usize = 8 + 1 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;
const SALT_CONTEXT: &str = "vault-password-salt-v1";

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

pub(crate) fn validate_new_password(password: &str) -> Result<(), &'static str> {
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

fn prompt_for_confirmed_password(require_minimum: bool) -> String {
    loop {
        let mut p1 = rpassword::prompt_password("Enter a password: ").unwrap_or_else(|error| {
            eprintln!("Error: could not read password: {error}");
            std::process::exit(1);
        });
        let mut p2 =
            rpassword::prompt_password("Re-enter the password: ").unwrap_or_else(|error| {
                eprintln!("Error: could not read password confirmation: {error}");
                std::process::exit(1);
            });
        if require_minimum && let Err(error) = validate_new_password(&p1) {
            println!("{error}. Try again.");
        } else if p1 == p2 {
            p2.zeroize();
            return p1;
        } else {
            println!("Passwords don't match. Try again.")
        }
        p1.zeroize();
        p2.zeroize();
    }
}

pub fn prompt_for_password() -> String {
    prompt_for_confirmed_password(false)
}

pub fn prompt_for_new_master_password() -> String {
    prompt_for_confirmed_password(true)
}

fn generate_key(path: &std::path::Path) -> Result<[u8; 32], String> {
    let key = <[u8; 32]>::generate();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("could not create key file {}: {e}", path.display()))?;
    let result = set_private_perms(path)
        .map_err(|e| format!("could not protect key file {}: {e}", path.display()))
        .and_then(|_| {
            file.write_all(&key)
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
    if let Err(error) = result {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(key)
}

fn master_key_from_password_with_params(
    password: &str,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Option<[u8; 32]> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(32)).ok()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    let result =
        run_cpu_intensive(|| argon2.hash_password_into(password.as_bytes(), salt, &mut key));
    if result.is_err() {
        key.zeroize();
        return None;
    }
    Some(key)
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
pub fn try_gen_master_key(key_pass: &mut PasswordType, new: bool) -> Result<[u8; 32], String> {
    let key =
        match key_pass {
            PasswordType::Key(key) => {
                let file_path = if new {
                    new_key_file_path(key)?
                } else {
                    key_file_path(key)?
                };
                if new {
                    master_key_from_keyfile(&generate_key(&file_path)?)
                } else {
                    master_key_from_keyfile(&read(&file_path).map_err(|e| {
                        format!("could not read key file {}: {e}", file_path.display())
                    })?)
                }
            }
            PasswordType::Password(pass) => master_key_from_password(
                pass,
                &blake3::derive_key(SALT_CONTEXT, pass.as_bytes())[..SALT_LEN],
            ),
            PasswordType::Session { .. } => {
                return Err("an unlocked session key cannot derive another master key".to_string());
            }
        };
    Ok(key)
}

#[cfg(test)]
pub fn gen_master_key(key_pass: &mut PasswordType, new: bool) -> [u8; 32] {
    try_gen_master_key(key_pass, new).expect("could not derive master key")
}

fn encryption_key_from_master(master_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("vault-encryption-v1", master_key)
}

fn encryption_master(key_pass: &mut PasswordType, salt: &[u8]) -> Result<[u8; 32], String> {
    match key_pass {
        PasswordType::Password(pass) => Ok(master_key_from_password(pass, salt)),
        PasswordType::Key(_) => try_gen_master_key(key_pass, false),
        PasswordType::Session { .. } => {
            Err("an unlocked session key cannot be used with a different salt".to_string())
        }
    }
}

#[cfg(test)]
pub fn try_encrypt_file(key_pass: &mut PasswordType, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    try_encrypt_file_in_place(key_pass, plaintext.to_vec())
}

pub fn try_encrypt_file_in_place(
    key_pass: &mut PasswordType,
    mut plaintext: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let cached = match key_pass {
        PasswordType::Session {
            encryption_key,
            salt,
            kdf,
            memory_kib,
            iterations,
            parallelism,
        } => Some((
            *encryption_key,
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
        .map(|(_, _, _, parameters)| parameters)
        .unwrap_or_else(active_kdf_parameters);
    let salt = cached.map_or_else(<[u8; SALT_LEN]>::generate, |(_, salt, _, _)| salt);
    let kdf = match cached {
        Some((_, _, kdf, _)) => kdf,
        None => match key_pass {
            PasswordType::Password(_) => KDF_ARGON2ID,
            PasswordType::Key(_) => KDF_KEYFILE,
            PasswordType::Session { .. } => unreachable!(),
        },
    };
    let mut enc_key = if let Some((key, _, _, _)) = cached {
        key
    } else {
        let mut master_key = encryption_master(key_pass, &salt)?;
        let key = encryption_key_from_master(&master_key);
        master_key.zeroize();
        key
    };
    let mut session_key = enc_key;
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
    if cipher
        .encrypt_in_place(&nonce, &header, &mut plaintext)
        .is_err()
    {
        plaintext.zeroize();
        session_key.zeroize();
        return Err("encryption failure".to_string());
    }
    let ciphertext_len = plaintext.len();
    plaintext.reserve(HEADER_LEN);
    plaintext.resize(ciphertext_len + HEADER_LEN, 0);
    plaintext.copy_within(..ciphertext_len, HEADER_LEN);
    plaintext[..HEADER_LEN].copy_from_slice(&header);
    if !matches!(key_pass, PasswordType::Session { .. }) {
        let mut original = std::mem::replace(key_pass, PasswordType::Password(String::new()));
        original.zeroize();
        *key_pass = PasswordType::Session {
            encryption_key: session_key,
            salt,
            kdf,
            memory_kib: parameters.memory_kib,
            iterations: parameters.iterations,
            parallelism: parameters.parallelism,
        };
    }
    session_key.zeroize();
    Ok(plaintext)
}

#[cfg(test)]
pub fn encrypt_file(key_pass: &mut PasswordType, plaintext: &[u8]) -> Vec<u8> {
    try_encrypt_file(key_pass, plaintext).expect("could not encrypt vault")
}

pub fn decrypt_file(key_pass: &mut PasswordType, encrypted: &[u8]) -> Option<Vec<u8>> {
    if !encrypted.starts_with(VAULT_MAGIC)
        || encrypted.len() < HEADER_LEN + 16
        || encrypted[8] != VAULT_VERSION
    {
        return None;
    }

    // Versioned format: magic, version, KDF parameters, salt, nonce, ciphertext.
    let kdf = encrypted[9];
    let memory_kib = u32::from_be_bytes(encrypted[10..14].try_into().ok()?);
    let iterations = u32::from_be_bytes(encrypted[14..18].try_into().ok()?);
    let parallelism = u32::from_be_bytes(encrypted[18..22].try_into().ok()?);
    if !(8 * 1024..=1024 * 1024).contains(&memory_kib)
        || !(1..=10).contains(&iterations)
        || !(1..=16).contains(&parallelism)
    {
        return None;
    }
    let salt = &encrypted[22..22 + SALT_LEN];
    let nonce_start = 22 + SALT_LEN;
    let nonce_end = nonce_start + NONCE_LEN;
    let nonce = XNonce::try_from(&encrypted[nonce_start..nonce_end]).ok()?;
    let cached_key = match &*key_pass {
        PasswordType::Session {
            encryption_key,
            salt: cached_salt,
            kdf: cached_kdf,
            memory_kib: cached_memory_kib,
            iterations: cached_iterations,
            parallelism: cached_parallelism,
        } if cached_salt.as_slice() == salt
            && *cached_kdf == kdf
            && *cached_memory_kib == memory_kib
            && *cached_iterations == iterations
            && *cached_parallelism == parallelism =>
        {
            Some(*encryption_key)
        }
        _ => None,
    };
    let mut enc_key = if let Some(key) = cached_key {
        key
    } else {
        let mut master = match (&*key_pass, kdf) {
            (PasswordType::Password(password), KDF_ARGON2ID) => {
                master_key_from_password_with_params(
                    password,
                    salt,
                    memory_kib,
                    iterations,
                    parallelism,
                )?
            }
            (PasswordType::Key(_), KDF_KEYFILE) => try_gen_master_key(key_pass, false).ok()?,
            _ => return None,
        };
        let key = encryption_key_from_master(&master);
        master.zeroize();
        key
    };
    let session_key = enc_key;
    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    enc_key.zeroize();
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &encrypted[nonce_end..],
                aad: &encrypted[..nonce_end],
            },
        )
        .ok()?;
    if !matches!(key_pass, PasswordType::Session { .. }) {
        let mut original = std::mem::replace(key_pass, PasswordType::Password(String::new()));
        original.zeroize();
        *key_pass = PasswordType::Session {
            encryption_key: session_key,
            salt: salt.try_into().ok()?,
            kdf,
            memory_kib,
            iterations,
            parallelism,
        };
    }
    Some(plaintext)
}

#[cfg(test)]
#[path = "encryption_tests.rs"]
mod test;
