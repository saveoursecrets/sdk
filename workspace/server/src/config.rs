use std::path::Path;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

use sos_core::address::AddressStr;

use crate::Result;

fn default_false() -> bool {
    false
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_false")]
    pub gui: bool,
    pub users: HashMap<AddressStr, UserConfig>,
}

impl ServerConfig {
    /// Load a server config from a file path.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(path.as_ref())?;
        let config: ServerConfig = toml::from_str(&contents)?;
        Ok(config)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserConfig {

}
