//! Server configuration.
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};
use url::Url;

use super::backend::Backend;
use super::{Error, Result};

use sos_sdk::{signer::ecdsa::Address, vfs};

/// Configuration for the web server.
#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Storage for the backend.
    pub storage: StorageConfig,

    /// Configuration for TLS encryption.
    pub tls: Option<TlsConfig>,

    /// Access controls.
    pub access: AccessControlConfig,

    /// Configuration for CORS.
    pub cors: CorsConfig,

    /// Path the file was loaded from used to determine
    /// relative paths.
    #[serde(skip)]
    file: Option<PathBuf>,
}

/// Access control configuration.
///
/// Denied entries take precedence so if you allow and
/// deny the same address it will be denied.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AccessControlConfig {
    /// Addresses that are explicitly allowed.
    pub allow: Option<HashSet<Address>>,
    /// Addresses that are explicitly denied.
    pub deny: Option<HashSet<Address>>,
}

impl AccessControlConfig {
    /// Determine if a signing key address is allowed access
    /// to this server.
    pub fn is_allowed_access(&self, address: &Address) -> bool {
        let has_definitions = self.allow.is_some() || self.deny.is_some();
        if has_definitions {
            match (&self.deny, &self.allow) {
                (Some(deny), None) => {
                    if deny.iter().any(|a| a == address) {
                        return false;
                    }
                    true
                }
                (None, Some(allow)) => {
                    if allow.iter().any(|a| a == address) {
                        return true;
                    }
                    false
                }
                (Some(deny), Some(allow)) => {
                    if allow.iter().any(|a| a == address) {
                        return true;
                    }
                    if deny.iter().any(|a| a == address) {
                        return false;
                    }
                    false
                }
                _ => true,
            }
        } else {
            true
        }
    }
}

/// Certificate and key for TLS.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the certificate.
    pub cert: PathBuf,
    /// Path to the certificate key file.
    pub key: PathBuf,
}

/// Configuration for CORS.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CorsConfig {
    /// List of additional CORS origins for the server.
    pub origins: Vec<Url>,
}

/// Configuration for storage locations.
#[derive(Debug, Serialize, Deserialize)]
pub struct StorageConfig {
    /// URL for the backend storage.
    pub path: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("."),
        }
    }
}

impl ServerConfig {
    /// Load a server config from a file path.
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        if !vfs::try_exists(path.as_ref()).await? {
            return Err(Error::NotFile(path.as_ref().to_path_buf()));
        }

        let contents = vfs::read_to_string(path.as_ref()).await?;
        let mut config: ServerConfig = toml::from_str(&contents)?;
        config.file = Some(path.as_ref().canonicalize()?);

        let dir = config.directory();

        if let Some(tls) = config.tls.as_mut() {
            if tls.cert.is_relative() {
                tls.cert = dir.join(&tls.cert);
            }
            if tls.key.is_relative() {
                tls.key = dir.join(&tls.key);
            }

            tls.cert = tls.cert.canonicalize()?;
            tls.key = tls.key.canonicalize()?;
        }

        Ok(config)
    }

    /// Parent directory of the configuration file.
    fn directory(&self) -> PathBuf {
        self.file
            .as_ref()
            .unwrap()
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap()
    }

    /// Get the backend implementation.
    pub async fn backend(&self) -> Result<Backend> {
        // Config file directory for relative file paths.
        let dir = self.directory();

        let path = &self.storage.path;
        let path = if path.is_relative() {
            dir.join(path)
        } else {
            path.to_owned()
        };

        let mut backend = Backend::new(path);
        backend.read_dir().await?;
        Ok(backend)
    }
}
