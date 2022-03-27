use std::path::Path;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

use crate::Result;

#[derive(Serialize, Deserialize)]
pub struct ServerConfig {
    users: HashMap<String, UserConfig>,
}

impl ServerConfig {
    /// Load a server config from a file path.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(path.as_ref())?;
        let config: ServerConfig = toml::from_str(&contents)?;
        Ok(config)
    }
}

#[derive(Serialize, Deserialize)]
pub struct UserConfig {

}
