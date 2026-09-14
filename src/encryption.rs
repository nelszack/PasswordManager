use crate::file::{data_dir, set_private_perms};
use crate::types::PasswordType;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit, Payload},
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
const ARGON_MEMORY_KIB: u32 = 64 * 1024;
const ARGON_ITERATIONS: u32 = 3;
const ARGON_PARALLELISM: u32 = 1;
const LEGACY_SALT: &[u8] = b"vault-master-key-salt-v1";
const SALT_CONTEXT: &str = "vault-password-salt-v1";

pub fn prompt_for_password() -> String {
    loop {
        let p1 = rpassword::prompt_password("Enter a password: ").unwrap_or_else(|error| {
            eprintln!("Error: could not read password: {error}");
            std::process::exit(1);
        });
        let p2 = rpassword::prompt_password("Re-enter the password: ").unwrap_or_else(|error| {
            eprintln!("Error: could not read password confirmation: {error}");
            std::process::exit(1);
        });
        if p1 == p2 {
            return p1;
        }
        println!("Passwords don't match. Try again.")
    }
}

fn generate_key(path: &std::path::Path) -> Result<[u8; 32], String> {
    let key = <[u8; 32]>::generate();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("could not create key file {}: {e}", path.display()))?;
    let result = file
        .write_all(&key)
        .map_err(|e| format!("could not write key file {}: {e}", path.display()))
        .and_then(|_| {
            file.sync_all()
                .map_err(|e| format!("could not sync key file {}: {e}", path.display()))
        })
        .and_then(|_| {
            set_private_perms(path)
                .map_err(|e| format!("could not protect key file {}: {e}", path.display()))
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
    if argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .is_err()
    {
        key.zeroize();
        return None;
    }
    Some(key)
}

fn master_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    master_key_from_password_with_params(
        password,
        salt,
        ARGON_MEMORY_KIB,
        ARGON_ITERATIONS,
        ARGON_PARALLELISM,
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
                let file_path = data_dir().join(key);
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
        };
    Ok(key)
}

#[cfg(test)]
pub fn gen_master_key(key_pass: &mut PasswordType, new: bool) -> [u8; 32] {
    try_gen_master_key(key_pass, new).expect("could not derive master key")
}

pub fn try_gen_master_key_legacy(key_pass: &mut PasswordType) -> Result<[u8; 32], String> {
    let key = match key_pass {
        PasswordType::Key(key) => {
            let file_path = data_dir().join(key);
            master_key_from_keyfile(
                &read(&file_path)
                    .map_err(|e| format!("could not read key file {}: {e}", file_path.display()))?,
            )
        }
        PasswordType::Password(pass) => master_key_from_password(pass, LEGACY_SALT),
    };
    Ok(key)
}

fn encryption_key_from_master(master_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("vault-encryption-v1", master_key)
}

fn encryption_master(key_pass: &mut PasswordType, salt: &[u8]) -> Result<[u8; 32], String> {
    match key_pass {
        PasswordType::Password(pass) => Ok(master_key_from_password(pass, salt)),
        PasswordType::Key(_) => try_gen_master_key(key_pass, false),
    }
}

pub fn try_encrypt_file(key_pass: &mut PasswordType, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let salt = <[u8; SALT_LEN]>::generate();
    let kdf = match key_pass {
        PasswordType::Password(_) => KDF_ARGON2ID,
        PasswordType::Key(_) => KDF_KEYFILE,
    };
    let mut master_key = encryption_master(key_pass, &salt)?;
    let mut enc_key = encryption_key_from_master(&master_key);
    master_key.zeroize();
    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    enc_key.zeroize();
    let nonce = XNonce::generate();
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(VAULT_MAGIC);
    header.push(VAULT_VERSION);
    header.push(kdf);
    header.extend_from_slice(&ARGON_MEMORY_KIB.to_be_bytes());
    header.extend_from_slice(&ARGON_ITERATIONS.to_be_bytes());
    header.extend_from_slice(&ARGON_PARALLELISM.to_be_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .expect("encryption failure");
    Ok([header.as_slice(), ciphertext.as_slice()].concat())
}

#[cfg(test)]
pub fn encrypt_file(key_pass: &mut PasswordType, plaintext: &[u8]) -> Vec<u8> {
    try_encrypt_file(key_pass, plaintext).expect("could not encrypt vault")
}

fn decrypt_with(
    key_pass: &mut PasswordType,
    salt: &[u8],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let mut master_key = encryption_master(key_pass, salt).ok()?;
    let mut enc_key = encryption_key_from_master(&master_key);
    master_key.zeroize();
    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    enc_key.zeroize();
    let nonce = XNonce::try_from(nonce_bytes).ok()?;
    cipher.decrypt(&nonce, ciphertext).ok()
}

pub fn decrypt_file(key_pass: &mut PasswordType, encrypted: &[u8]) -> Option<Vec<u8>> {
    if encrypted.len() < NONCE_LEN {
        return None;
    }

    // Versioned format: magic, version, KDF parameters, salt, nonce, ciphertext.
    if encrypted.starts_with(VAULT_MAGIC) {
        if encrypted.len() < HEADER_LEN + 16 || encrypted[8] != VAULT_VERSION {
            return None;
        }
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
        let mut enc_key = encryption_key_from_master(&master);
        master.zeroize();
        let cipher = XChaCha20Poly1305::new((&enc_key).into());
        enc_key.zeroize();
        return cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &encrypted[nonce_end..],
                    aad: &encrypted[..nonce_end],
                },
            )
            .ok();
    }

    // Previous format: salt(16) || nonce(24) || ciphertext.
    if encrypted.len() >= SALT_LEN + NONCE_LEN {
        let salt = &encrypted[..SALT_LEN];
        let (nonce_bytes, ciphertext) = encrypted[SALT_LEN..].split_at(NONCE_LEN);
        if let Some(plaintext) = decrypt_with(key_pass, salt, nonce_bytes, ciphertext) {
            return Some(plaintext);
        }
    }

    // Legacy format: nonce(24) || ciphertext with a fixed salt
    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_LEN);
    decrypt_with(key_pass, LEGACY_SALT, nonce_bytes, ciphertext)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{fs, path::Path};
    #[test]
    fn test_encrypt_decrypt_pass() {
        let plaintext = "this is a test".as_bytes();
        let mut pass = PasswordType::Password("test123".into());
        let encrypt = encrypt_file(&mut pass, plaintext);
        let decrypt = decrypt_file(&mut pass, &encrypt).unwrap();
        assert_eq!(decrypt, plaintext)
    }
    #[test]
    fn test_encrypt_decrypt_key() {
        crate::file::init_test_data_dir();
        let temp = Path::new("temp.enc");
        gen_master_key(&mut PasswordType::Key("temp.enc".to_string()), true);
        let plaintext = "this is a test".as_bytes();
        let mut pass = PasswordType::Key(temp.to_str().unwrap().to_string());
        let encrypt = encrypt_file(&mut pass, plaintext);
        let decrypt = decrypt_file(&mut pass, &encrypt).unwrap();
        let file_path = data_dir().join(temp);
        fs::remove_file(file_path).unwrap();
        assert_eq!(decrypt, plaintext)
    }
    #[test]
    fn test_encrypt_decrypt_empty_plaintext() {
        let plaintext = b"";
        let mut pass = PasswordType::Password("test123".into());
        let encrypt = encrypt_file(&mut pass, plaintext);
        let decrypt = decrypt_file(&mut pass, &encrypt).unwrap();
        assert_eq!(decrypt, plaintext);
    }
    #[test]
    fn test_encrypt_decrypt_large_plaintext() {
        let plaintext = vec![0u8; 10000];
        let mut pass = PasswordType::Password("test123".into());
        let encrypt = encrypt_file(&mut pass, &plaintext);
        let decrypt = decrypt_file(&mut pass, &encrypt).unwrap();
        assert_eq!(decrypt, plaintext);
    }
    #[test]
    fn test_decrypt_invalid_data_returns_none() {
        let mut pass = PasswordType::Password("test123".into());
        let result = decrypt_file(&mut pass, b"short");
        assert!(result.is_none());
    }
    #[test]
    fn test_decrypt_wrong_password_returns_none() {
        let plaintext = "secret data".as_bytes();
        let mut pass1 = PasswordType::Password("password1".into());
        let encrypt = encrypt_file(&mut pass1, plaintext);
        let mut pass2 = PasswordType::Password("password2".into());
        let result = decrypt_file(&mut pass2, &encrypt);
        assert!(result.is_none());
    }
    #[test]
    fn test_decrypt_corrupted_ciphertext_returns_none() {
        let plaintext = "test".as_bytes();
        let mut pass = PasswordType::Password("test123".into());
        let mut encrypt = encrypt_file(&mut pass, plaintext);
        encrypt[24] ^= 0xFF;
        let result = decrypt_file(&mut pass, &encrypt);
        assert!(result.is_none());
    }
    #[test]
    fn test_encrypt_produces_different_output_each_time() {
        let plaintext = "test".as_bytes();
        let mut pass = PasswordType::Password("test123".into());
        let encrypt1 = encrypt_file(&mut pass, plaintext);
        let encrypt2 = encrypt_file(&mut pass, plaintext);
        assert_ne!(
            encrypt1, encrypt2,
            "Encryption should produce unique ciphertexts due to random nonce"
        );
    }
    #[test]
    fn test_encrypted_data_contains_nonce() {
        let plaintext = "test".as_bytes();
        let mut pass = PasswordType::Password("test123".into());
        let encrypt = encrypt_file(&mut pass, plaintext);
        assert!(
            encrypt.len() > plaintext.len(),
            "Encrypted data should be larger than plaintext"
        );
        assert!(
            encrypt.len() >= 24 + plaintext.len(),
            "Nonce (24 bytes) + ciphertext"
        );
    }
    #[test]
    fn test_legacy_format_still_decrypts() {
        let plaintext = b"legacy vault data";
        let mut pass = PasswordType::Password("test123".into());
        let enc_key = encryption_key_from_master(&master_key_from_password("test123", LEGACY_SALT));
        let cipher = XChaCha20Poly1305::new((&enc_key).into());
        let nonce = XNonce::generate();
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_slice()).unwrap();
        let legacy = [nonce.as_slice(), ciphertext.as_slice()].concat();
        let dec = decrypt_file(&mut pass, &legacy).unwrap();
        assert_eq!(dec, plaintext);
    }
    #[test]
    fn test_encrypt_uses_random_salt() {
        let plaintext = b"same plaintext";
        let mut pass = PasswordType::Password("test123".into());
        let e1 = encrypt_file(&mut pass, plaintext);
        let e2 = encrypt_file(&mut pass, plaintext);
        const SALT_OFFSET: usize = 8 + 1 + 1 + 4 + 4 + 4;
        assert_ne!(
            &e1[SALT_OFFSET..SALT_OFFSET + SALT_LEN],
            &e2[SALT_OFFSET..SALT_OFFSET + SALT_LEN]
        );
    }

    #[test]
    fn authenticated_header_rejects_tampering() {
        let mut pass = PasswordType::Password("test123".into());
        let encrypted = encrypt_file(&mut pass, b"sensitive vault data");
        for offset in [8, 9, 10, 22, HEADER_LEN - 1] {
            let mut tampered = encrypted.clone();
            tampered[offset] ^= 1;
            assert!(
                decrypt_file(&mut pass, &tampered).is_none(),
                "tampered header byte {offset} was accepted"
            );
        }
    }

    #[test]
    fn authenticated_ciphertext_rejects_tampering_and_truncation() {
        let mut pass = PasswordType::Password("test123".into());
        let encrypted = encrypt_file(&mut pass, b"sensitive vault data");
        let mut tampered = encrypted.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(decrypt_file(&mut pass, &tampered).is_none());
        assert!(decrypt_file(&mut pass, &encrypted[..encrypted.len() - 1]).is_none());
    }

    #[test]
    fn hostile_kdf_parameters_are_rejected_before_derivation() {
        let mut pass = PasswordType::Password("test123".into());
        let encrypted = encrypt_file(&mut pass, b"sensitive vault data");
        for memory_kib in [0, 1024 * 1024 + 1] {
            let mut hostile = encrypted.clone();
            hostile[10..14].copy_from_slice(&(memory_kib as u32).to_be_bytes());
            assert!(decrypt_file(&mut pass, &hostile).is_none());
        }
    }
}
