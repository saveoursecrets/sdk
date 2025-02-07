//! Server configuration.
use super::backend::Backend;
use super::{Error, Result};
use serde::{Deserialize, Serialize};
use sos_backend::BackendTarget;
use sos_core::{AccountId, Paths};
use sos_database::{migrations::migrate_client, open_file};
use sos_vfs as vfs;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};
use url::Url;

/// Configuration for the web server.
#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Storage for the backend.
    pub storage: StorageConfig,

    /// Log configuration.
    pub log: LogConfig,

    /// Access controls.
    pub access: Option<AccessControlConfig>,

    /// Configuration for the network.
    pub net: NetworkConfig,

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
    /// AccountIdes that are explicitly allowed.
    pub allow: Option<HashSet<AccountId>>,
    /// AccountIdes that are explicitly denied.
    pub deny: Option<HashSet<AccountId>>,
}

impl AccessControlConfig {
    /// Determine if a signing key address is allowed access
    /// to this server.
    pub fn is_allowed_access(&self, account_id: &AccountId) -> bool {
        let has_definitions = self.allow.is_some() || self.deny.is_some();
        if has_definitions {
            match (&self.deny, &self.allow) {
                (Some(deny), None) => {
                    if deny.iter().any(|a| a == account_id) {
                        return false;
                    }
                    true
                }
                (None, Some(allow)) => {
                    if allow.iter().any(|a| a == account_id) {
                        return true;
                    }
                    false
                }
                (Some(deny), Some(allow)) => {
                    if allow.iter().any(|a| a == account_id) {
                        return true;
                    }
                    if deny.iter().any(|a| a == account_id) {
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

/// Log file configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Directory for log files.
    pub directory: PathBuf,
    /// Name of log files.
    pub name: String,
    /// Tracing level.
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("logs"),
            name: "sos-server.log".to_string(),
            level: "sos_server=info".to_string(),
        }
    }
}

/// Server network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// Bind address for the server.
    pub bind: SocketAddr,

    /// SSL configuration.
    pub ssl: Option<SslConfig>,

    /// Configuration for CORS.
    pub cors: Option<CorsConfig>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                5053,
            ),
            ssl: Default::default(),
            cors: None,
        }
    }
}

/// Server SSL configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", untagged)]
pub enum SslConfig {
    /// Configuration for TLS certificate and private key.
    Tls(TlsConfig),
    /// Configuration for Let's Encrypt ACME certificates.
    #[cfg(feature = "acme")]
    Acme(AcmeConfig),
}

/// Certificate and key for TLS.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the certificate.
    pub cert: PathBuf,
    /// Path to the certificate key file.
    pub key: PathBuf,
}

/// Configuration for ACME certficates.
#[cfg(feature = "acme")]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// Path to the cache directory.
    pub cache: PathBuf,
    /// List of domain names.
    pub domains: Vec<String>,
    /// List of email addresses.
    pub email: Vec<String>,
    /// Use production environment.
    pub production: bool,
}

/// Configuration for CORS.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CorsConfig {
    /// List of additional CORS origins for the server.
    pub origins: Vec<Url>,
}

/// Configuration for storage locations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// URL for the backend storage.
    pub path: PathBuf,

    /// Database file.
    ///
    /// When this field is given the server will use
    /// the database backend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,

    /// Parsed database URI.
    #[serde(skip)]
    pub database_uri: Option<UriOrPath>,
}

/// URI or path reference.
#[derive(Debug, Clone)]
pub enum UriOrPath {
    /// URI reference.
    Uri(http::Uri),
    /// Path reference.
    Path(PathBuf),
}

impl UriOrPath {
    /// URI string representation.
    pub fn as_uri_string(&self) -> String {
        match self {
            UriOrPath::Uri(uri) => uri.to_string(),
            UriOrPath::Path(path) => format!("file:{}", path.display()),
        }
    }
}

impl StorageConfig {
    fn set_database_uri(
        &mut self,
        db: &str,
        base_dir: impl AsRef<Path>,
    ) -> Result<()> {
        let uri = if db.starts_with("file:") {
            UriOrPath::Uri(db.parse()?)
        } else {
            let path = PathBuf::from(db);

            println!("{:#?}", base_dir.as_ref());

            if path.is_relative() {
                let path = base_dir.as_ref().join(path);
                if !path.exists() {
                    std::fs::File::create(&path)?;
                }
                UriOrPath::Path(path.canonicalize()?)
            } else {
                UriOrPath::Path(path)
            }
        };

        self.database_uri = Some(uri);
        Ok(())
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("."),
            database: None,
            database_uri: None,
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

        if config.log.directory.is_relative() {
            config.log.directory = dir.join(&config.log.directory);
            if !config.log.directory.exists() {
                vfs::create_dir_all(&config.log.directory).await?;
            }
            config.log.directory = config.log.directory.canonicalize()?;
        }

        if let Some(SslConfig::Tls(tls)) = &mut config.net.ssl {
            if tls.cert.is_relative() {
                tls.cert = dir.join(&tls.cert);
            }
            if tls.key.is_relative() {
                tls.key = dir.join(&tls.key);
            }

            tls.cert = tls.cert.canonicalize()?;
            tls.key = tls.key.canonicalize()?;
        }

        if let Some(db) = &config.storage.database.clone() {
            config.storage.set_database_uri(db, config.directory())?;
        }

        Ok(config)
    }

    /// Set the server bind address.
    pub fn set_bind_address(&mut self, addr: SocketAddr) {
        self.net.bind = addr;
    }

    /// Server bind address.
    pub fn bind_address(&self) -> &SocketAddr {
        &self.net.bind
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
        let path = path.canonicalize()?;

        let paths = Paths::new_global_server(&path);

        let target = if let Some(uri) = &self.storage.database_uri {
            tracing::debug!(database_uri = % uri.as_uri_string());
            let mut client = open_file(uri.as_uri_string()).await?;
            migrate_client(&mut client).await?;
            BackendTarget::Database(client)
        } else {
            BackendTarget::FileSystem(paths.clone())
        };

        let mut backend = Backend::new(paths, target);
        backend.load_accounts().await?;
        Ok(backend)
    }
}
