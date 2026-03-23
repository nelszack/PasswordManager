use crate::cli::ConfigArgs;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Config {
    pub genpass: Genpassconf,
    pub clpboard: Clpbconf,
    pub unlock: Unlockconf,
    pub copy: Copyconf,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Genpassconf {
    pub length: u8,
    pub stats: bool,
    pub copy: bool,
}
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Copyconf {
    pub copy_pass: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Clpbconf {
    pub clp_timeout: u8,
}
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Unlockconf {
    pub unlock_timeout: u8,
}

fn write_file(config: &Config, config_path: &Path) {
    let toml_string = toml::to_string(config).unwrap();
    fs::write(config_path, &toml_string).unwrap();
}
fn default_config(write_to_file: bool, config_path: &Path) -> Config {
    let config = Config {
        genpass: Genpassconf {
            length: 12,
            stats: false,
            copy: true,
        },
        clpboard: Clpbconf { clp_timeout: 15 },
        unlock: Unlockconf { unlock_timeout: 0 },
        copy: Copyconf { copy_pass: true },
    };
    if write_to_file {
        write_file(&config, config_path)
    }
    return config;
}
fn is_config(config_path: &Path) -> bool {
    if Path::new(config_path).exists() {
        return true;
    }
    return false;
}
pub fn read_config(config_path: &Path) -> Config {
    if !is_config(config_path) {
        return default_config(true, config_path);
    }
    let txt = std::fs::read_to_string(config_path).unwrap();
    let config = match toml::from_str(&txt) {
        Ok(content) => content,
        Err(_) => {
            fix_new_config(default_config(false, config_path), &txt, config_path);
            read_config(config_path)
        }
    };
    return config;
}
fn fix_new_config(config: Config, old_config_txt: &str, config_path: &Path) {
    let mut new = ConfigArgs {
        defalt: false,
        genpass_copy: None,
        genpass_length: None,
        genpass_stats: None,
        clpb_timeout: None,
        unlock_timeout: None,
    };
    let tre = old_config_txt.split("\n\n").collect::<Vec<&str>>();
    for i in tre {
        let peices = i.split("\n").collect::<Vec<&str>>();
        let trimmed = peices[0]
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap();
        for j in &peices[1..] {
            let sp = j.split('\n').collect::<String>();
            let thing = sp.split(" = ").collect::<Vec<&str>>();
            match (trimmed, thing[0]) {
                ("genpass", "length") => {
                    new.genpass_length = Some(thing[1].parse().unwrap());
                }
                ("genpass", "stats") => {
                    new.genpass_stats = Some(thing[1].parse().unwrap());
                }
                ("genpass", "copy") => {
                    new.genpass_copy = Some(thing[1].parse().unwrap());
                }
                ("clpboard", "clp_timeout") => {
                    new.clpb_timeout = Some(thing[1].parse().unwrap());
                }
                ("unlock", "unlock_timeout") => {
                    new.unlock_timeout = Some(thing[1].parse().unwrap());
                }
                _ => {}
            }
        }
    }
    update(config, new, config_path);
}
pub fn update(mut config: Config, modify: ConfigArgs, config_path: &Path) {
    if modify.defalt {
        config = default_config(false, config_path);
    }
    if let Some(i) = modify.genpass_length {
        config.genpass.length = i;
    }
    if let Some(i) = modify.genpass_stats {
        config.genpass.stats = i
    }
    if let Some(i) = modify.genpass_copy {
        config.genpass.copy = i
    }
    if let Some(i) = modify.clpb_timeout {
        config.clpboard.clp_timeout = i
    }
    if let Some(i) = modify.unlock_timeout {
        config.unlock.unlock_timeout = i
    }
    write_file(&config, config_path);
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env;

    #[test]
    fn test_config() {
        let config_path = env::temp_dir();
        let config_file = config_path.join("config.toml");
        test_read_write(&config_file);
        test_update(&config_file);
    }
    fn test_read_write(config_path: &Path) {
        let conf1 = read_config(config_path);
        default_config(true, config_path);
        let conf2 = read_config(config_path);
        assert_eq!(
            conf2,
            Config {
                genpass: Genpassconf {
                    length: 12,
                    stats: false,
                    copy: true
                },
                clpboard: Clpbconf { clp_timeout: 15 },
                unlock: Unlockconf { unlock_timeout: 0 },
                copy: Copyconf { copy_pass: true }
            }
        );
        write_file(&conf1, config_path);
        assert_eq!(read_config(config_path), conf1)
    }

    fn test_update(config_path: &Path) {
        let conf1 = read_config(config_path);
        update(
            default_config(true, config_path),
            ConfigArgs {
                defalt: false,
                genpass_length: Some(100),
                genpass_stats: Some(false),
                genpass_copy: Some(true),
                clpb_timeout: Some(12),
                unlock_timeout: Some(15),
            },
            config_path,
        );
        assert_eq!(
            read_config(config_path),
            Config {
                genpass: Genpassconf {
                    length: 100,
                    stats: false,
                    copy: true
                },
                clpboard: Clpbconf { clp_timeout: 12 },
                unlock: Unlockconf { unlock_timeout: 15 },
                copy: Copyconf { copy_pass: true }
            }
        );
        write_file(&conf1, config_path);
    }
}
