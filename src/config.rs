use crate::{ConfigArgs, file_exists};
use serde::{Deserialize, Serialize};
use std::fs;
const CONFIG_PATH: &str = "config.toml";

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub genpass: Genpassconf,
    pub clpboard: Clpbconf,
}

#[derive(Serialize, Deserialize)]
pub struct Genpassconf {
    pub length: u8,
    pub stats: bool,
}

#[derive(Serialize, Deserialize)]
pub struct Clpbconf {
    pub timeout: u8,
}

fn default_config(write_to_file: bool) -> Config {
    let config = Config {
        genpass: Genpassconf {
            length: 12,
            stats: true,
        },
        clpboard: Clpbconf { timeout: 10 },
    };
    if write_to_file {
        let toml_string = toml::to_string(&config).unwrap();
        fs::write(CONFIG_PATH, &toml_string).unwrap();
    }
    return config;
}

pub fn read_config() -> Config {
    if !file_exists(CONFIG_PATH) {
        return default_config(true);
    }
    let text = std::fs::read_to_string(CONFIG_PATH).unwrap();
    let config: Config = toml::from_str(&text).unwrap();
    return config;
}

pub fn update(modify: ConfigArgs) {
    let mut config: Config = read_config();
    if modify.defalt {
        config = default_config(false);
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
    let toml_string = toml::to_string_pretty(&config).unwrap();
    fs::write(CONFIG_PATH, &toml_string).unwrap();
}
