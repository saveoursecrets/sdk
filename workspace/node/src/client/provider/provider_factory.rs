//! Factory for creating providers.
use sos_core::{
    signer::BoxedSigner,
    wal::{file::WalFile, WalProvider},
    PatchFile, PatchProvider,
};
use std::{
    fmt,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, RwLock},
};
use url::Url;
use web3_address::ethereum::Address;

use crate::{
    cache_dir,
    client::{
        changes_listener::ChangesListener,
        net::RpcClient,
        provider::{
            LocalProvider, RemoteProvider, StorageDirs, StorageProvider,
        },
        Error, Result,
    },
};

/// Factory for creating providers.
#[derive(Debug)]
pub enum ProviderFactory {
    /// Local provider using the default cache location.
    Local,
    /// Specific directory location.
    Directory(PathBuf),
    /// Remote server.
    Remote(Url),
}

impl fmt::Display for ProviderFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Directory(path) => write!(f, "{}", path.display()),
            Self::Remote(remote) => write!(f, "{}", remote),
        }
    }
}

impl Default for ProviderFactory {
    fn default() -> Self {
        Self::Remote(Url::parse("http://localhost:5053").unwrap())
    }
}

impl ProviderFactory {
    /// Create a provider.
    pub fn create_provider(
        &self,
        signer: BoxedSigner,
    ) -> Result<(FileCache<WalFile, PatchFile>, Address)> {
        match self {
            Self::Local => {
                let dir = cache_dir().ok_or_else(|| Error::NoCache)?;
                Ok(new_local_file_provider(signer, dir)?)
            }
            Self::Directory(dir) => {
                if !dir.is_dir() {
                    return Err(Error::NotDirectory(dir.clone()));
                }
                Ok(new_local_file_provider(signer, dir.clone())?)
            }
            Self::Remote(remote) => {
                let dir = cache_dir().ok_or_else(|| Error::NoCache)?;
                Ok(new_remote_file_provider(signer, dir, remote.clone())?)
            }
        }
    }
}

impl FromStr for ProviderFactory {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s == "local" {
            Ok(Self::Local)
        } else {
            match s.parse::<Url>() {
                Ok(url) => {
                    let scheme = url.scheme();
                    if scheme == "http" || scheme == "https" {
                        Ok(Self::Remote(url))
                    } else if scheme == "file" {
                        let path = s.trim_start_matches("file://");
                        Ok(Self::Directory(PathBuf::from(path)))
                    } else {
                        Err(Error::InvalidProvider(s.to_string()))
                    }
                }
                Err(e) => Err(e.into()),
            }
        }
    }
}

/// Type alias for a file node cache.
type FileCache<W, P> =
    Arc<RwLock<Box<dyn StorageProvider<W, P> + Send + Sync + 'static>>>;

/// Spawn a change notification listener that
/// updates the local node cache.
pub fn spawn_changes_listener<W, P>(
    server: Url,
    signer: BoxedSigner,
    cache: FileCache<W, P>,
) where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    let listener = ChangesListener::new(server, signer);
    listener.spawn(move |notification| {
        let cache = Arc::clone(&cache);
        async move {
            //println!("{:#?}", notification);
            let mut writer = cache.write().unwrap();
            let _ = writer.handle_change(notification).await;
        }
    });
}

/// Create a new remote provider with a local disc mirror.
pub fn new_remote_file_provider(
    signer: BoxedSigner,
    cache_dir: PathBuf,
    server: Url,
) -> Result<(FileCache<WalFile, PatchFile>, Address)> {
    let address = signer.address()?;
    let client = RpcClient::new(server, signer);
    let dirs = StorageDirs::new(cache_dir, &address.to_string());
    let provider: Box<
        dyn StorageProvider<WalFile, PatchFile> + Send + Sync + 'static,
    > = Box::new(RemoteProvider::new_file_cache(client, dirs)?);
    Ok((Arc::new(RwLock::new(provider)), address))
}

/// Create a new local provider.
pub fn new_local_file_provider(
    signer: BoxedSigner,
    cache_dir: PathBuf,
) -> Result<(FileCache<WalFile, PatchFile>, Address)> {
    let address = signer.address()?;
    let dirs = StorageDirs::new(cache_dir, &address.to_string());
    let provider: Box<
        dyn StorageProvider<WalFile, PatchFile> + Send + Sync + 'static,
    > = Box::new(LocalProvider::new_file_storage(dirs)?);
    Ok((Arc::new(RwLock::new(provider)), address))
}
