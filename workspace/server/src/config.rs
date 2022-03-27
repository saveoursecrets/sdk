use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use url::{Host, Url};

use sos_core::address::AddressStr;

use crate::{Error, Result, Backend, FileSystemBackend};

fn default_false() -> bool {
    false
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_false")]
    pub gui: bool,
    pub users: HashMap<AddressStr, UserConfig>,
    #[serde(skip)]
    file: Option<PathBuf>,
}

impl ServerConfig {
    /// Load a server config from a file path.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(path.as_ref())?;
        let mut config: ServerConfig = toml::from_str(&contents)?;
        config.file = Some(path.as_ref().canonicalize()?);
        Ok(config)
    }
}

impl ServerConfig {
    /// Map each user config to a backend implementation.
    pub fn backends(&self) -> Result<HashMap<AddressStr, Box<dyn Backend>>> {
        // Config file directory for relative paths.
        let dir = self
            .file
            .as_ref()
            .unwrap()
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap();
        let mut backends = HashMap::new();
        for (addr, user) in self.users.iter() {
            backends.insert(addr.clone(), user.backend(&dir)?);
        }
        Ok(backends)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserConfig {
    url: Url,
}

impl UserConfig {
    /// Get the back implementation for a user configuration.
    fn backend<P: AsRef<Path>>(&self, dir: P) -> Result<Box<dyn Backend>> {
        match self.url.scheme() {
            "file" => {
                let url = self.url.clone();
                let mut is_relative = false;
                if let Some(host) = url.host() {
                    if let Host::Domain(name) = host {
                        if name == "." {
                            is_relative = true;
                        }
                    }
                }
                let url = if is_relative {
                    let base_file = format!(
                        "file://{}",
                        dir.as_ref().to_string_lossy().into_owned()
                    );
                    let mut base: Url = base_file.parse()?;
                    // Must end with a slash to join the relative path
                    // correctly
                    if !base.path().ends_with("/") {
                        let path = format!("{}/", base.path());
                        base.set_path(&path);
                    }

                    let path = format!(".{}", url.path());
                    base.join(&path)?
                } else {
                    url
                };

                let path = url
                    .to_file_path()
                    .map_err(|_| Error::UrlFilePath(self.url.clone()))?;

                let mut backend = FileSystemBackend::new(path);
                backend.read_dir()?;
                Ok(Box::new(backend))
            }
            _ => Err(Error::InvalidUrlScheme(self.url.scheme().to_string())),
        }
    }
}
