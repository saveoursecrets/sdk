//! Factory for creating providers.
use async_trait::async_trait;
use sos_core::{
    events::{WalEvent},
    signer::BoxedSigner,
    wal::{file::WalFile, WalProvider, memory::WalMemory, snapshot::SnapShotManager},
    PatchFile, PatchProvider, PatchMemory,
    vault::{Summary, Vault, VaultId},
};
use std::{
    fmt,
    collections::HashMap,
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
            BoxedProvider, ProviderState,
        },
        Error, Result,
    },
};

/// Provider that can be safely sent between threads.
pub type ArcProvider<W, P> = Arc<RwLock<BoxedProvider<W, P>>>;

/*
/// Enumeration of the provider concrete types.
pub enum Provider {
    /// Storage provider backed by files on disc.
    File(BoxedProvider<WalFile, PatchFile>),
    /// Storage provider backed by memory.
    Memory(BoxedProvider<WalMemory, PatchMemory<'static>>),
}

macro_rules! enum_proxy_call {
    ( $name:ident, $self:expr $( , $arg:ident )* ) => {
        match $self {
            Self::File(o) => o.$name($($arg),*),
            Self::Memory(o) => o.$name($($arg),*),
        }
    };
}

macro_rules! enum_proxy_call_async {
    ( $name:ident, $self:expr $( , $arg:ident )* ) => {
        match $self {
            Self::File(o) => o.$name($($arg),*).await,
            Self::Memory(o) => o.$name($($arg),*).await,
        }
    };
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StorageProvider<WalFile, PatchFile> for Provider {
    fn state(&self) -> &ProviderState {
        enum_proxy_call!(state, self)
    }

    fn state_mut(&mut self) -> &mut ProviderState {
        enum_proxy_call!(state_mut, self)
    }

    fn dirs(&self) -> &StorageDirs {
        enum_proxy_call!(dirs, self)
    }

    fn cache(&self) -> &HashMap<VaultId, (WalFile, PatchFile)> {
        enum_proxy_call!(cache, self)
    }

    fn cache_mut(&mut self) -> &mut HashMap<VaultId, (WalFile, PatchFile)> {
        enum_proxy_call!(cache_mut, self)
    }

    fn snapshots(&self) -> Option<&SnapShotManager> {
        enum_proxy_call!(snapshots, self)
    }

    async fn update_vault<'a>(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<WalEvent<'a>>,
    ) -> Result<()> {
        enum_proxy_call_async!(update_vault, self, summary, vault, events)
    }

    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)>;
    async fn refresh_vault(
        &mut self,
        summary: &Summary,
        new_passphrase: Option<&SecretString>,
    ) -> Result<()>;
    async fn create_account_with_buffer(
        &mut self,
        buffer: Vec<u8>,
    ) -> Result<Summary>;
    async fn create_vault_or_account(
        &mut self,
        name: Option<String>,
        passphrase: Option<String>,
        _is_account: bool,
    ) -> Result<(SecretString, Summary)>;
    async fn remove_vault(&mut self, summary: &Summary) -> Result<()>;
    async fn load_vaults(&mut self) -> Result<&[Summary]>;
    async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<()>;
    async fn open_vault(
        &mut self,
        summary: &Summary,
        passphrase: &str,
    ) -> Result<()>;
    async fn reduce_wal(&mut self, summary: &Summary) -> Result<Vault>;
    async fn patch(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'static>>,
    ) -> Result<()>;
    async fn handle_change(
        &mut self,
        change: ChangeNotification,
    ) -> Result<(bool, HashSet<ChangeAction>)>;
}
*/

/// Factory for creating providers.
#[derive(Debug)]
pub enum ProviderFactory {
    /*
    /// Provider storing data in memory.
    Memory,
    */

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
            //Self::Memory => write!(f, "memory"),
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

    /*
    /// Create a provider.
    pub fn create_provider2(
        &self,
        signer: BoxedSigner,
    ) -> Result<(Provider, Address)> {
        match self {
            Self::Memory => {
                let (provider, address) = new_local_memory_provider(signer)?;
                Ok((Provider::Memory(provider), address))
            }
            Self::Local => {
                let dir = cache_dir().ok_or_else(|| Error::NoCache)?;
                let (provider, address) = 
                    new_local_file_provider(signer, dir)?;
                Ok((Provider::File(provider), address))
            }
            Self::Directory(dir) => {
                if !dir.is_dir() {
                    return Err(Error::NotDirectory(dir.clone()));
                }
                let (provider, address) = 
                    new_local_file_provider(signer, dir.clone())?;
                Ok((Provider::File(provider), address))
            }
            Self::Remote(remote) => {
                let dir = cache_dir().ok_or_else(|| Error::NoCache)?;
                let (provider, address) = 
                    new_remote_file_provider(signer, dir, remote.clone())?;
                Ok((Provider::File(provider), address))
            }
        }
    }
    */

    /// Create a provider.
    pub fn create_provider(
        &self,
        signer: BoxedSigner,
    ) -> Result<(BoxedProvider<WalFile, PatchFile>, Address)> {
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
            //_ => todo!()
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

/// Spawn a change notification listener that
/// updates the local node cache.
pub fn spawn_changes_listener<W, P>(
    server: Url,
    signer: BoxedSigner,
    cache: ArcProvider<W, P>,
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
) -> Result<(BoxedProvider<WalFile, PatchFile>, Address)> {
    let address = signer.address()?;
    let client = RpcClient::new(server, signer);
    let dirs = StorageDirs::new(cache_dir, &address.to_string());
    let provider: BoxedProvider<WalFile, PatchFile> = 
        Box::new(RemoteProvider::new_file_cache(client, dirs)?);
    Ok((provider, address))
}

/// Create a new local provider.
pub fn new_local_file_provider(
    signer: BoxedSigner,
    cache_dir: PathBuf,
) -> Result<(BoxedProvider<WalFile, PatchFile>, Address)> {
    let address = signer.address()?;
    let dirs = StorageDirs::new(cache_dir, &address.to_string());
    let provider: BoxedProvider<WalFile, PatchFile> = 
        Box::new(LocalProvider::new_file_storage(dirs)?);
    Ok((provider, address))
}

/// Create a new local memory provider.
pub fn new_local_memory_provider(
    signer: BoxedSigner,
) -> Result<(BoxedProvider<WalMemory, PatchMemory<'static>>, Address)> {
    let address = signer.address()?;
    let provider: BoxedProvider<WalMemory, PatchMemory> = 
        Box::new(LocalProvider::new_memory_storage());
    Ok((provider, address))
}
