use crate::vault::{Vault, VaultEnteries, VaultFns};
use std::path::Path;

pub fn file_exists(file_path: &str) -> bool {
    if Path::new(file_path).exists() {
        return true;
    }
    return false;
}

pub fn import(path: String, vlt: &mut Option<Vault>) {
    let mut rdr = csv::Reader::from_path(path).unwrap();
    for i in rdr.deserialize() {
        let ent: VaultEnteries = i.unwrap();
        // println!("{:?}",ent);
        vlt.append(&mut vec![ent]);
    }
}
