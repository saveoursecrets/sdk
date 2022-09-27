//! Client implementations for the SPOT (Single Point of Truth)
//! networking mode.

/// Client implementations that write to disc.
#[cfg(not(target_arch = "wasm32"))]
pub mod file {

    use sos_core::{
        signer::BoxedSigner, vault::Summary, wal::file::WalFile, PatchFile,
    };
    use std::{
        path::PathBuf,
        sync::{Arc, RwLock},
    };
    use url::Url;

    use crate::client::{
        changes_listener::ChangesListener,
        net::RpcClient,
        provider::{RemoteProvider, StorageDirs, StorageProvider},
        Result,
    };

    /// Type alias for a file node cache.
    pub type FileCache = Arc<RwLock<RemoteProvider<WalFile, PatchFile>>>;

    /// Client that communicates with a single server and
    /// writes it's cache to disc.
    pub struct SpotFileClient {
        cache: FileCache,
        changes: ChangesListener,
    }

    impl SpotFileClient {
        /// Create a new SPOT file client.
        pub fn new(
            server: Url,
            signer: BoxedSigner,
            cache_dir: PathBuf,
        ) -> Result<Self> {
            let changes =
                ChangesListener::new(server.clone(), signer.clone());

            let address = signer.address()?;
            let client = RpcClient::new(server, signer);
            let dirs = StorageDirs::new(cache_dir, &address.to_string());

            let cache = Arc::new(RwLock::new(
                RemoteProvider::new_file_cache(client, dirs)?,
            ));
            Ok(Self { cache, changes })
        }

        /// Get a clone of the underlying node cache.
        pub fn cache(&self) -> FileCache {
            Arc::clone(&self.cache)
        }

        /// Spawn a change notification listener that
        /// updates the local node cache.
        pub fn spawn_changes(&self) {
            let cache = self.cache();
            let listener = self.changes.clone();
            listener.spawn(move |notification| {
                let cache = Arc::clone(&cache);
                async move {
                    //println!("{:#?}", notification);
                    let mut writer = cache.write().unwrap();
                    let _ = writer.handle_change(notification).await;
                }
            });
        }

        /*
        /// Create an account on the local filesystem.
        pub async fn create_local_account<D: AsRef<Path>>(
            &self,
            cache_dir: D,
            buffer: Vec<u8>,
        ) -> Result<Summary> {
            let summary = Header::read_summary_slice(&buffer)?;

            let reader = self.cache.read().unwrap();
            let user_dir =
                ensure_user_vaults_dir(cache_dir, reader.signer())?;

            // Write out the vault
            let mut vault_path = user_dir.join(summary.id().to_string());
            vault_path.set_extension(Vault::extension());
            std::fs::write(&vault_path, &buffer)?;

            // Write the WAL file
            let mut wal_path = user_dir.join(summary.id().to_string());
            wal_path.set_extension(WalFile::extension());
            let mut wal = WalFile::new(&wal_path)?;
            let event = WalEvent::CreateVault(Cow::Owned(buffer));
            wal.append_event(event)?;

            Ok(summary)
        }
        */

        /*
        /// Create an account on a remote node.
        pub async fn create_remote_account(
            &self,
            buffer: Vec<u8>,
        ) -> Result<(u16, Summary)> {
            let summary = Header::read_summary_slice(&buffer)?;
            let reader = self.cache.read().unwrap();
            // We don't use the create_account() function on
            // NodeCache as that will assign a passphrase and
            // in this case we expect the client to have chosen
            // a passphrase for the vault rather than having a
            // passphrase assigned.
            let status =
                reader.client().create_account(buffer).await?.into_status();

            if status != StatusCode::OK {
                return Err(Error::ResponseCode(status.into()));
            }

            Ok((status.into(), summary))
        }
        */

        /// List the vault summaries.
        pub async fn load_vaults(&mut self) -> Result<Vec<Summary>> {
            let mut writer = self.cache.write().unwrap();
            let summaries = writer.load_vaults().await?.to_vec();
            Ok(summaries)
        }

        /// Open a vault.
        pub async fn open_vault(
            &mut self,
            summary: Summary,
            passphrase: String,
        ) -> Result<()> {
            let mut writer = self.cache.write().unwrap();
            writer.open_vault(&summary, &passphrase).await?;
            Ok(())
        }

        /// Close the currently open vault.
        pub fn close_vault(&mut self) -> Result<()> {
            let mut writer = self.cache.write().unwrap();
            writer.close_vault();
            Ok(())
        }
    }
}

/// Client implementation that stores data in memory.
///
/// Designed to use static futures so that they may be driven
/// from webassembly created by `wasm-bindgen`.
#[cfg(target_arch = "wasm32")]
pub mod memory {
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
    pub struct SpotMemoryClient {
        cache: MemoryCache,
        url: Url,
        signer: BoxedSigner,
    }

    impl SpotMemoryClient {
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
}
