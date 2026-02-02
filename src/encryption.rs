use crate::files::PassType;
use crate::vault::{DecryptEntry, Entry};
use argon2::{Argon2, Params};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::Rng;
use rand::RngCore;
use sha2::Sha256;
use std::{fs::File, io::Write};

const NOMALIZATION_SALT: &[u8] = b"normalizarion_salt_v1";
fn from_password(pass: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(NOMALIZATION_SALT), pass.as_bytes());
    hk.expand(b"normalize", &mut out).unwrap();
    out
}

pub fn generate_file_name(pass: &PassType) -> String {
    let salt = b"salt_for_finding_correct_file_v1";
    let hk = match pass {
        PassType::Word(s) => Hkdf::<Sha256>::new(Some(salt), &from_password(s)),
        PassType::Key(k) => Hkdf::<Sha256>::new(Some(salt), k),
        _ => panic!("PassType shouldnt be Empty"),
    };
    let mut okm = [0u8; 12];
    let _ = hk.expand(b"filename", &mut okm);
    let fname = URL_SAFE_NO_PAD.encode(okm);
    fname
}

pub fn generate_key(path: &std::path::Path) -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill(&mut key);
    let mut file = File::create(path).unwrap();
    file.write_all(&key).unwrap();
    key
}

pub fn gen_nonce() -> [u8; 12] {
    let mut entry_nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut entry_nonce);
    entry_nonce
}

pub fn gen_master() -> [u8; 32] {
    let mut master_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut master_key);
    master_key
}
pub fn gen_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}
pub fn argon2_endcryption(key_pass: &Vec<u8>, salt: [u8; 16]) -> [u8; 32] {
    let params = Params::new(32 * 1024, 3, 1, None).unwrap();
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut d_key = [0u8; 32];
    argon2
        .hash_password_into(key_pass, &salt, &mut d_key)
        .unwrap();
    d_key
}
pub fn wrap_key(d_key: &mut [u8; 32], master_key: &mut [u8], nonce: [u8; 12]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(d_key));
    let wrap_key = cipher
        .encrypt(Nonce::from_slice(&nonce), &master_key[..])
        .unwrap();
    wrap_key
}
pub fn decrypt_e(master_key: &[u8], entries: Vec<Entry>) -> Vec<DecryptEntry> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&master_key));
    let mut d_entries: Vec<DecryptEntry> = Vec::new();
    for i in entries {
        let plain = cipher
            .decrypt(Nonce::from_slice(&i.nonce), i.ciphertext.as_ref())
            .unwrap();
        d_entries.push(DecryptEntry {
            id: i.id,
            text: plain,
        });
    }
    d_entries
}
// pub fn encrypt_e(master_key: &[u8], entries: Vec<DecryptEntry>) -> Vec<Entry> {
//     let cipher = ChaCha20Poly1305::new(Key::from_slice(master_key));
//     let mut enc_entrys = Vec::new();
//     for i in entries {
//         let nonce = gen_nonce();
//         let enc = cipher
//             .encrypt(Nonce::from_slice(&nonce), i.text.as_ref())
//             .unwrap();
//         enc_entrys.push(Entry {
//             id: i.id,
//             nonce: nonce.to_vec(),
//             ciphertext: enc,
//         });
//     }
//     enc_entrys
// }
