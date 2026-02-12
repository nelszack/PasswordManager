use crate::file::file_exists;
use crate::types::PasswordType;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    AeadCore, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::Rng;
use rand_core::OsRng;
use std::{
    fs::{File, read},
    io::Write,
    path::Path,
};

pub fn create_password() -> String {
    loop {
        let p1 = rpassword::prompt_password("enter password ").unwrap();
        let p2 = rpassword::prompt_password("enter password again ").unwrap();
        if p1 == p2 {
            return p1;
        }
        println!("passwords dont match try again")
    }
}

fn generate_key(path: &std::path::Path) -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill(&mut key);
    if file_exists(&path.as_os_str().to_str().unwrap()) {
        panic!("Key file already exists choose a different name for file")
    }
    let mut file = File::create(path).unwrap();
    file.write_all(&key).unwrap();
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
            if new {
                master_key_from_keyfile(&generate_key(&Path::new(&key)))
            } else {
                master_key_from_keyfile(&read(format!("{}", key)).unwrap())
            }
        }
        PasswordType::Password(pass) => {
            if new {
                *pass = Some(create_password());

                master_key_from_password(&pass.as_ref().unwrap(), b"vault-master-key-salt-v1")
            } else {
                master_key_from_password(&pass.as_ref().unwrap(), b"vault-master-key-salt-v1")
            }
        }
    }
}

fn encryption_key_from_master(master_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("vault-encryption-v1", master_key)
}

pub fn encrypt_file(mut key_pass: PasswordType, plaintext: &[u8]) -> Vec<u8> {
    let enc_key = encryption_key_from_master(&gen_master_key(&mut key_pass, false));
    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("encryption failure");
    [nonce.as_slice(), &ciphertext].concat()
}

pub fn decrypt_file(mut key_pass: &mut PasswordType, encrypted: &[u8]) -> Option<Vec<u8>> {
    if encrypted.len() < 24 {
        return None;
    }

    let enc_key = encryption_key_from_master(&gen_master_key(&mut key_pass, false));
    let cipher = XChaCha20Poly1305::new((&enc_key).into());

    let (nonce_bytes, ciphertext) = encrypted.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext).ok()
}
