use crate::file::{data_dir, file_exists, set_private_perms};
use crate::types::PasswordType;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    AeadCore, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::Rng;
use rand::rngs::OsRng;
use std::{
    fs::{File, read},
    io::Write,
};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const LEGACY_SALT: &[u8] = b"vault-master-key-salt-v1";
const SALT_CONTEXT: &str = "vault-password-salt-v1";

pub fn prompt_for_password() -> String {
    loop {
        let p1 = rpassword::prompt_password("Enter a password: ").unwrap();
        let p2 = rpassword::prompt_password("Re-enter the password: ").unwrap();
        if p1 == p2 {
            return p1;
        }
        println!("Passwords don't match. Try again.")
    }
}

fn generate_key(path: &std::path::Path) -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill(&mut key);
    if file_exists(path) {
        panic!("Key file already exists. Choose a different name.")
    }
    let mut file = File::create(path).unwrap();
    file.write_all(&key).unwrap();
    set_private_perms(path);
    key
}

fn master_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let params = Params::new(64 * 1024, 3, 1, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .unwrap();

    key
}
fn master_key_from_keyfile(keyfile_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(keyfile_bytes).as_bytes()
}
pub fn gen_master_key(key_pass: &mut PasswordType, new: bool) -> [u8; 32] {
    match key_pass {
        PasswordType::Key(key) => {
            let file_path = data_dir().join(key);
            if new {
                master_key_from_keyfile(&generate_key(&file_path))
            } else {
                master_key_from_keyfile(&read(&file_path).unwrap())
            }
        }
        PasswordType::Password(pass) => master_key_from_password(
            pass,
            &blake3::derive_key(SALT_CONTEXT, pass.as_bytes())[..SALT_LEN],
        ),
    }
}

pub fn gen_master_key_legacy(key_pass: &mut PasswordType) -> [u8; 32] {
    match key_pass {
        PasswordType::Key(key) => {
            let file_path = data_dir().join(key);
            master_key_from_keyfile(&read(&file_path).unwrap())
        }
        PasswordType::Password(pass) => master_key_from_password(pass, LEGACY_SALT),
    }
}

fn encryption_key_from_master(master_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("vault-encryption-v1", master_key)
}

fn encryption_master(key_pass: &mut PasswordType, salt: &[u8]) -> [u8; 32] {
    match key_pass {
        PasswordType::Password(pass) => master_key_from_password(pass, salt),
        PasswordType::Key(_) => gen_master_key(key_pass, false),
    }
}

pub fn encrypt_file(key_pass: &mut PasswordType, plaintext: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill(&mut salt);
    let enc_key = encryption_key_from_master(&encryption_master(key_pass, &salt));
    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("encryption failure");
    [salt.as_slice(), nonce.as_slice(), ciphertext.as_slice()].concat()
}

fn decrypt_with(
    key_pass: &mut PasswordType,
    salt: &[u8],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let enc_key = encryption_key_from_master(&encryption_master(key_pass, salt));
    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).ok()
}

pub fn decrypt_file(key_pass: &mut PasswordType, encrypted: &[u8]) -> Option<Vec<u8>> {
    if encrypted.len() < NONCE_LEN {
        return None;
    }

    // New format: salt(16) || nonce(24) || ciphertext
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
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
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
        assert_ne!(&e1[..SALT_LEN], &e2[..SALT_LEN]);
    }
}
