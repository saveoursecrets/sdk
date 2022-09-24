//! Server configuration.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use url::{Host, Url};

use super::backend::{Backend, FileSystemBackend};
use super::{Error, Result};

/// Configuration for the web server.
#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Whether to serve the web GUI.
    pub gui: bool,

    /// Audit log file.
    pub audit: AuditConfig,

    /// Storage for the backend.
    pub storage: StorageConfig,

    /// Settings for session management.
    pub session: SessionConfig,

    /// Configuration for TLS encryption.
    pub tls: Option<TlsConfig>,

    /// Configuration for the API.
    pub api: ApiConfig,

    /// Path the file was loaded from used to determine
    /// relative paths.
    #[serde(skip)]
    file: Option<PathBuf>,
}

impl ServerConfig {
    /// Create a new server config with a file path.
    pub fn new_dummy_file(path: PathBuf) -> Self {
        let mut config: Self = Default::default();
        config.file = Some(path);
        config
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the certificate.
    pub cert: PathBuf,
    /// Path to the certificate key file.
    pub key: PathBuf,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ApiConfig {
    /// List of additional CORS origins for the server.
    pub origins: Vec<Url>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Duration for sessions in seconds.
    pub duration: u64,

    /// Interval in seconds to reap expired sessions.
    ///
    /// Default is every 30 minutes.
    pub reap_interval: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            duration: 900,
            reap_interval: 1800,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditConfig {
    /// File system path to the audit log.
    pub file: PathBuf,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            file: PathBuf::from("audit.dat"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StorageConfig {
    /// URL for the backend storage.
    pub url: Url,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            url: Url::parse("file://.").unwrap(),
        }
    }
}

impl ServerConfig {
    /// Load a server config from a file path.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        if !path.as_ref().exists() {
            return Err(Error::NotFile(path.as_ref().to_path_buf()));
        }

        let contents = std::fs::read_to_string(path.as_ref())?;
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

    /// Path to the audit log file.
    pub fn audit_file(&self) -> PathBuf {
        // Config file directory for relative file paths.
        let dir = self.directory();
        if self.audit.file.is_absolute() {
            self.audit.file.clone()
        } else {
            dir.join(&self.audit.file)
        }
    }

    /// Get the backend implementation.
    pub async fn backend(&self) -> Result<Box<dyn Backend + Send + Sync>> {
        // Config file directory for relative file paths.
        let dir = self.directory();

        match self.storage.url.scheme() {
            "file" => {
                let url = self.storage.url.clone();
                let mut is_relative = false;
                let relative_prefix =
                    if let Some(Host::Domain(name)) = url.host() {
                        if name == "." || name == ".." {
                            is_relative = true;
                            Some(name)
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                let url = if is_relative {
                    let base_file = format!(
                        "file://{}",
                        dir.to_string_lossy().into_owned()
                    );
                    let mut base: Url = base_file.parse()?;
                    // Must end with a slash to join the relative path
                    // correctly
                    if !base.path().ends_with('/') {
                        let path = format!("{}/", base.path());
                        base.set_path(&path);
                    }

                    let rel_prefix = relative_prefix.unwrap_or(".");
                    let path = format!("{}{}", rel_prefix, url.path());
                    base.join(&path)?
                } else {
                    url
                };

                let path = url.to_file_path().map_err(|_| {
                    Error::UrlFilePath(self.storage.url.clone())
                })?;

                let mut backend = FileSystemBackend::new(path);
                backend.read_dir().await?;
                Ok(Box::new(backend))
            }
            _ => Err(Error::InvalidUrlScheme(
                self.storage.url.scheme().to_string(),
            )),
        }
    }
}
