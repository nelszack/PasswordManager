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
    use std::{env, fs, fs::File};

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
    #[test]
    fn test_is_config_exists() {
        let config_path = env::temp_dir().join("test_exists.toml");
        File::create(&config_path).unwrap();
        assert!(is_config(&config_path));
        fs::remove_file(&config_path).unwrap();
    }
    #[test]
    fn test_is_config_not_exists() {
        let config_path = env::temp_dir().join("nonexistent_config.toml");
        assert!(!is_config(&config_path));
    }
    #[test]
    fn test_update_single_field() {
        let config_path = env::temp_dir().join("test_single.toml");
        default_config(true, &config_path);
        update(
            read_config(&config_path),
            ConfigArgs {
                defalt: false,
                genpass_length: Some(24),
                genpass_stats: None,
                genpass_copy: None,
                clpb_timeout: None,
                unlock_timeout: None,
            },
            &config_path,
        );
        let conf = read_config(&config_path);
        assert_eq!(conf.genpass.length, 24);
        assert_eq!(conf.genpass.stats, false);
        fs::remove_file(&config_path).unwrap();
    }
    #[test]
    fn test_default_config_values() {
        let config = default_config(false, &Path::new("dummy.toml"));
        assert_eq!(config.genpass.length, 12);
        assert!(!config.genpass.stats);
        assert!(config.genpass.copy);
        assert_eq!(config.clpboard.clp_timeout, 15);
        assert_eq!(config.unlock.unlock_timeout, 0);
        assert!(config.copy.copy_pass);
    }
    #[test]
    fn test_reset_to_default() {
        let config_path = env::temp_dir().join("test_reset.toml");
        update(
            read_config(&config_path),
            ConfigArgs {
                defalt: true,
                genpass_length: Some(100),
                genpass_stats: Some(true),
                genpass_copy: Some(false),
                clpb_timeout: Some(30),
                unlock_timeout: Some(5),
            },
            &config_path,
        );
        update(
            read_config(&config_path),
            ConfigArgs {
                defalt: true,
                genpass_length: None,
                genpass_stats: None,
                genpass_copy: None,
                clpb_timeout: None,
                unlock_timeout: None,
            },
            &config_path,
        );
        let conf = read_config(&config_path);
        assert_eq!(conf.genpass.length, 12);
        assert!(!conf.genpass.stats);
        assert!(conf.genpass.copy);
        fs::remove_file(&config_path).unwrap();
    }

    #[test]
    fn test_config_with_alternate_values() {
        let config_path = env::temp_dir().join("alternate.toml");
        let content = r#"
[genpass]
length = 20
stats = true
copy = false

[clpboard]
clp_timeout = 30

[unlock]
unlock_timeout = 5

[copy]
copy_pass = false
"#;
        fs::write(&config_path, content).unwrap();
        let conf = read_config(&config_path);
        assert_eq!(conf.genpass.length, 20);
        assert!(conf.genpass.stats);
        assert!(!conf.genpass.copy);
        assert_eq!(conf.clpboard.clp_timeout, 30);
        assert_eq!(conf.unlock.unlock_timeout, 5);
        assert!(!conf.copy.copy_pass);
        fs::remove_file(&config_path).unwrap();
    }

    #[test]
    fn test_multiple_updates() {
        let config_path = env::temp_dir().join("multiple.toml");
        default_config(true, &config_path);

        update(
            read_config(&config_path),
            ConfigArgs {
                defalt: false,
                genpass_length: Some(16),
                genpass_stats: Some(true),
                genpass_copy: None,
                clpb_timeout: None,
                unlock_timeout: None,
            },
            &config_path,
        );

        update(
            read_config(&config_path),
            ConfigArgs {
                defalt: false,
                genpass_length: None,
                genpass_stats: None,
                genpass_copy: Some(false),
                clpb_timeout: Some(45),
                unlock_timeout: Some(10),
            },
            &config_path,
        );

        let conf = read_config(&config_path);
        assert_eq!(conf.genpass.length, 16);
        assert!(conf.genpass.stats);
        assert!(!conf.genpass.copy);
        assert_eq!(conf.clpboard.clp_timeout, 45);
        assert_eq!(conf.unlock.unlock_timeout, 10);
        fs::remove_file(&config_path).unwrap();
    }

    #[test]
    fn test_config_round_trip() {
        let config_path = env::temp_dir().join("roundtrip.toml");

        let original = Config {
            genpass: Genpassconf {
                length: 32,
                stats: true,
                copy: false,
            },
            clpboard: Clpbconf { clp_timeout: 60 },
            unlock: Unlockconf { unlock_timeout: 15 },
            copy: Copyconf { copy_pass: false },
        };

        write_file(&original, &config_path);
        let loaded = read_config(&config_path);

        assert_eq!(original, loaded);
        fs::remove_file(&config_path).unwrap();
    }

    #[test]
    fn test_config_update_zero_timeout() {
        let config_path = env::temp_dir().join("zero_timeout.toml");
        default_config(true, &config_path);
        update(
            read_config(&config_path),
            ConfigArgs {
                defalt: false,
                genpass_length: None,
                genpass_stats: None,
                genpass_copy: None,
                clpb_timeout: Some(0),
                unlock_timeout: Some(0),
            },
            &config_path,
        );
        let conf = read_config(&config_path);
        assert_eq!(conf.clpboard.clp_timeout, 0);
        assert_eq!(conf.unlock.unlock_timeout, 0);
        fs::remove_file(&config_path).unwrap();
    }

    #[test]
    fn test_config_update_max_values() {
        let config_path = env::temp_dir().join("max_values.toml");
        default_config(true, &config_path);
        update(
            read_config(&config_path),
            ConfigArgs {
                defalt: false,
                genpass_length: Some(u8::MAX),
                genpass_stats: Some(true),
                genpass_copy: Some(false),
                clpb_timeout: Some(u8::MAX),
                unlock_timeout: Some(u8::MAX),
            },
            &config_path,
        );
        let conf = read_config(&config_path);
        assert_eq!(conf.genpass.length, u8::MAX);
        assert!(conf.genpass.stats);
        assert!(!conf.genpass.copy);
        assert_eq!(conf.clpboard.clp_timeout, u8::MAX);
        assert_eq!(conf.unlock.unlock_timeout, u8::MAX);
        fs::remove_file(&config_path).unwrap();
    }

    #[test]
    fn test_config_preserves_unmodified_fields() {
        let config_path = env::temp_dir().join("preserve.toml");
        update(
            default_config(false, &config_path),
            ConfigArgs {
                defalt: false,
                genpass_length: Some(50),
                genpass_stats: None,
                genpass_copy: None,
                clpb_timeout: None,
                unlock_timeout: None,
            },
            &config_path,
        );
        let conf = read_config(&config_path);
        assert_eq!(conf.genpass.length, 50);
        assert!(!conf.genpass.stats);
        assert!(conf.genpass.copy);
        assert_eq!(conf.clpboard.clp_timeout, 15);
        assert_eq!(conf.unlock.unlock_timeout, 0);
        fs::remove_file(&config_path).unwrap();
    }
}
