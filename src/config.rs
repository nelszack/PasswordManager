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
pub struct Copyconf {
    pub time: u8,
}
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Genpassconf {
    pub length: u8,
    pub stats: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Clpbconf {
    pub timeout: u8,
}
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Unlockconf {
    pub timeout: u8,
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
        },
        clpboard: Clpbconf { timeout: 10 },
        unlock: Unlockconf { timeout: 0 },
        copy: Copyconf { time: 15 },
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
    let text = std::fs::read_to_string(config_path).unwrap();
    let config: Config = toml::from_str(&text).unwrap();
    return config;
}

pub fn update(modify: ConfigArgs, config_path: &Path) {
    let mut config: Config = read_config(config_path);
    if modify.defalt {
        config = default_config(false, config_path);
    }
    if let Some(i) = modify.genpass_length {
        config.genpass.length = i;
    }
    if let Some(i) = modify.genpass_stats {
        config.genpass.stats = i
    }
    if let Some(i) = modify.clpb_timeout {
        config.clpboard.timeout = i
    }
    if let Some(i) = modify.unlock_timeout {
        config.unlock.timeout = i
    }
    if let Some(i) = modify.copy_time {
        config.copy.time = i
    }
    write_file(&config, config_path);
}

#[cfg(test)]
mod test {
    use super::*;
    use directories::ProjectDirs;
    #[test]
    fn test_config() {
        let proj_dir = ProjectDirs::from("com", "myproject", "password_manager").unwrap();
        let config_path = proj_dir.config_dir();
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
                },
                clpboard: Clpbconf { timeout: 10 },
                unlock: Unlockconf { timeout: 0 },
                copy: Copyconf { time: 15 }
            }
        );
        write_file(&conf1, config_path);
        assert_eq!(read_config(config_path), conf1)
    }

    fn test_update(config_path: &Path) {
        let conf1 = read_config(config_path);
        update(
            ConfigArgs {
                defalt: false,
                genpass_length: Some(100),
                genpass_stats: Some(false),
                clpb_timeout: Some(12),
                unlock_timeout: Some(15),
                copy_time: Some(15),
            },
            config_path,
        );
        assert_eq!(
            read_config(config_path),
            Config {
                genpass: Genpassconf {
                    length: 100,
                    stats: false
                },
                clpboard: Clpbconf { timeout: 12 },
                unlock: Unlockconf { timeout: 15 },
                copy: Copyconf { time: 15 }
            }
        );
        write_file(&conf1, config_path);
    }
}
