//! Memory provider that communicates with a remote server.
//!
//! Uses static futures so they can be driven from webassembly.
use crate::client::{
    net::RpcClient,
    provider::{RemoteProvider, StorageProvider},
    Error, Result,
};
use secrecy::SecretString;
use sos_core::{
    events::{ChangeAction, ChangeNotification, SyncEvent},
    signer::BoxedSigner,
    vault::{Summary, Vault},
    wal::memory::WalMemory,
    PatchMemory,
};
use std::{
    collections::HashSet,
    future::Future,
    sync::{Arc, RwLock},
};
use url::Url;

use crate::sync::SyncInfo;

/// Type alias for an in-memory node cache.
pub type MemoryCache =
    Arc<RwLock<RemoteProvider<WalMemory, PatchMemory<'static>>>>;

/// Client that communicates with a single server and
/// writes it's cache to memory.
///
/// Uses static futures so that it can be used in webassembly.
pub struct MemoryProvider {
    cache: MemoryCache,
    url: Url,
    signer: BoxedSigner,
}

impl MemoryProvider {
    /// Create a new SPOT memory client.
    pub fn new(server: Url, signer: BoxedSigner) -> Self {
        let url = server.clone();
        let client_signer = signer.clone();
        let client = RpcClient::new(server, signer);
        let cache = Arc::new(RwLock::new(
            RemoteProvider::new_memory_cache(client),
        ));
        Self {
            cache,
            url,
            signer: client_signer,
        }
    }

    /// Get the URL of the remote node.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Get the signer.
    pub fn signer(&self) -> &BoxedSigner {
        &self.signer
    }

    /// Create a new client.
    pub fn new_client(&self) -> RpcClient {
        RpcClient::new(self.url.clone(), self.signer.clone())
    }

    /// Get a clone of the underlying node cache.
    pub fn cache(&self) -> MemoryCache {
        Arc::clone(&self.cache)
    }

    /// Authenticate for a session.
    pub fn authenticate(
        cache: MemoryCache,
    ) -> impl Future<Output = Result<()>> + 'static {
        async move {
            let mut writer = cache.write().unwrap();
            writer.authenticate().await?;
            Ok::<(), Error>(())
        }
    }

    /// Create an account.
    pub fn create_account(
        cache: MemoryCache,
        buffer: Vec<u8>,
    ) -> impl Future<Output = Result<Summary>> + 'static {
        async move {
            let mut writer = cache.write().unwrap();
            let summary =
                writer.create_account_with_buffer(buffer).await?;
            Ok(summary)
        }
    }

    /// List the vaults.
    pub fn list_vaults(
        cache: MemoryCache,
    ) -> impl Future<Output = Result<Vec<Summary>>> + 'static {
        async move {
            let mut writer = cache.write().unwrap();
            let vaults = writer.load_vaults().await?;
            Ok::<Vec<Summary>, Error>(vaults.to_vec())
        }
    }

    /// Create a vault.
    pub fn create_vault(
        cache: MemoryCache,
        name: String,
        passphrase: String,
    ) -> impl Future<Output = Result<Summary>> + 'static {
        async move {
            let mut writer = cache.write().unwrap();
            let (_, summary) =
                writer.create_vault(name, Some(passphrase)).await?;
            Ok::<Summary, Error>(summary)
        }
    }

    /// Open a vault.
    pub fn open_vault(
        cache: MemoryCache,
        summary: Summary,
        passphrase: String,
    ) -> impl Future<Output = Result<()>> + 'static {
        async move {
            let mut writer = cache.write().unwrap();
            writer.open_vault(&summary, &passphrase).await?;
            Ok::<(), Error>(())
        }
    }

    /// Remove a vault.
    pub fn remove_vault(
        cache: MemoryCache,
        summary: Summary,
    ) -> impl Future<Output = Result<()>> + 'static {
        async move {
            let mut writer = cache.write().unwrap();
            writer.remove_vault(&summary).await?;
            Ok::<(), Error>(())
        }
    }

    /// Pull a vault.
    pub fn pull(
        cache: MemoryCache,
        summary: Summary,
        force: bool,
    ) -> impl Future<Output = Result<SyncInfo>> + 'static {
        async move {
            let mut writer = cache.write().unwrap();
            let info = writer.pull(&summary, force).await?;
            Ok::<SyncInfo, Error>(info)
        }
    }

    /// Change the password for a vault.
    pub fn change_password(
        cache: MemoryCache,
        vault: Vault,
        current_passphrase: SecretString,
        new_passphrase: SecretString,
    ) -> impl Future<Output = Result<()>> + 'static {
        async move {
            let mut writer = cache.write().unwrap();
            writer
                .change_password(
                    &vault,
                    current_passphrase,
                    new_passphrase,
                )
                .await?;
            Ok::<(), Error>(())
        }
    }

    /// Rename a vault.
    pub fn rename_vault(
        cache: MemoryCache,
        summary: Summary,
        name: String,
    ) -> impl Future<Output = Result<()>> + 'static {
        async move {
            let mut writer = cache.write().unwrap();
            writer.set_vault_name(&summary, &name).await?;
            Ok::<(), Error>(())
        }
    }

    /// Patch a vault.
    pub fn patch(
        cache: MemoryCache,
        summary: Summary,
        events: Vec<SyncEvent<'static>>,
    ) -> impl Future<Output = Result<()>> + 'static {
        async move {
            let mut writer = cache.write().unwrap();
            writer.patch(&summary, events).await?;
            Ok::<(), Error>(())
        }
    }

    /// Send a patch of events infallibly.
    ///
    /// This is used to send read secret events for
    /// audit logging.
    pub fn send_events(
        cache: MemoryCache,
        summary: Summary,
        events: Vec<SyncEvent<'static>>,
    ) -> impl Future<Output = ()> + 'static {
        async move {
            let mut writer = cache.write().unwrap();
            let _ = writer.patch(&summary, events).await;
        }
    }

    /// Handle a change notification.
    pub fn handle_change(
        cache: MemoryCache,
        change: ChangeNotification,
    ) -> impl Future<Output = Result<(bool, HashSet<ChangeAction>)>> + 'static
    {
        async move {
            let mut writer = cache.write().unwrap();
            let result = writer.handle_change(change).await?;
            Ok::<_, Error>(result)
        }
    }
}
