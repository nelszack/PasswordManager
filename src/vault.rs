use crate::CreateArgs;
use crate::encryption::*;
use crate::files::PassType;
use crate::files::{file_exists,find_file};
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use zeroize::Zeroize;



#[derive(Serialize, Deserialize)]

enum Rtype {
    Password,
    Keyfile,
}
#[derive(Serialize, Deserialize)]

pub struct OpenVault {
    pub master_key: [u8; 32],
    meta_data: VaultMetadata,
    pub entries: Vec<DecryptEntry>,
}
#[derive(Serialize, Deserialize)]

struct KeyWrap {
    r#type: Rtype,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    wrapped_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]

pub struct Entry {
    pub id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
#[derive(Serialize, Deserialize)]

pub struct DecryptEntry {
    pub id: String,
    pub text: Vec<u8>,
}

#[derive(Serialize, Deserialize)]

struct VaultMetadata {
    name: String,
}

#[derive(Serialize, Deserialize)]

pub struct Vault {
    version: u8,
    vault_metadata: VaultMetadata,
    key_wraps: KeyWrap,
    entries: Vec<Entry>,
}

pub fn create_vault(thing: CreateArgs) {
    let mut key_pass: PassType;
    let key_type: Rtype;
    if let Some(path) = thing.key_file {
        key_pass = PassType::Key(generate_key(&Path::new(&path)));
        key_type = Rtype::Keyfile;
    } else {
        let pass = prompt_password("enter password: ").unwrap();
        let mut pass1 = prompt_password("Verify password: ").unwrap();
        if pass != pass1 {
            panic!("passwords dont match");
        }
        // key_wrap.r#type="password".to_string();
        key_pass = PassType::Word(pass);
        key_type = Rtype::Password;
        pass1.zeroize();
    }
    let fname: String = generate_file_name(&key_pass);
    if file_exists(&format!("{}.enc", fname)) {
        panic!("password/key already used for vault")
    }
    let mut master_key = gen_master();
    let nonce = gen_nonce();
    let salt = gen_salt();
    let mut d_key = argon2_endcryption(&key_pass.into_vec(), salt);
    let wrapped_key = wrap_key(&mut d_key, &mut master_key, nonce);
    let key_wrap = KeyWrap {
        r#type: key_type,
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        wrapped_key: wrapped_key,
    };
    let vlt = Vault {
        version: 1,
        vault_metadata: VaultMetadata { name: fname },
        key_wraps: key_wrap,
        entries: Vec::new(),
    };
    save_vault(vlt);
    key_pass.zeroize();
}

pub fn unlock_vault(mut vault: Vault, key_pass: &[u8]) -> OpenVault {
    let mut der_key = argon2_endcryption(
        &key_pass.to_vec(),
        vault
            .key_wraps
            .salt
            .try_into()
            .map_err(|_| "invalid size")
            .unwrap(),
    );
    let m_key: [u8; 32] = wrap_key(
        &mut der_key,
        &mut vault.key_wraps.wrapped_key,
        vault
            .key_wraps
            .nonce
            .try_into()
            .map_err(|_| "invalid size")
            .unwrap(),
    )
    .try_into()
    .map_err(|_| "invalid size")
    .unwrap();

    OpenVault {
        master_key: m_key,
        meta_data: vault.vault_metadata,
        entries: decrypt_e(&m_key, vault.entries),
    }
}

// pub fn lock_vault(open: OpenVault, key_wrap: KeyWrap) {
//     let vlt = Vault {
//         version: 1,
//         vault_metadata: open.meta_data,
//         key_wraps: key_wrap,
//         entries: encrypt_e(&open.master_key, open.entries),
//     };
//     save_vault(vlt);
// }

fn save_vault(vault: Vault) {
    let buf = rmp_serde::to_vec(&vault).unwrap();
    fs::write(format!("{}.enc", vault.vault_metadata.name), buf).unwrap();
}

pub fn unlock_vault_from_key_pass(key_pass: PassType)->OpenVault {
    let fname = find_file(&key_pass);
    let contents = fs::read(format!("{}.enc", fname)).unwrap();
    let vault = rmp_serde::from_slice(&contents).unwrap();
    let key=match key_pass {
        PassType::Key(k)=>unlock_vault(vault, &k),
        PassType::Word(l)=>unlock_vault(vault, l.as_bytes()),
        _=>panic!("no good")
        
    };
    key
}
