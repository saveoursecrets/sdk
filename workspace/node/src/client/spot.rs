//! Client implementations for the SPOT (Single Point of Truth)
//! networking mode.

/// Client implementations that write to disc.
#[cfg(not(target_arch = "wasm32"))]
pub mod file {

    use sos_core::{
        signer::BoxedSigner,
        vault::Summary,
        wal::{file::WalFile, WalProvider},
        PatchFile, PatchProvider,
    };
    use std::{
        path::PathBuf,
        sync::{Arc, RwLock},
    };
    use url::Url;
    use web3_address::ethereum::Address;

    use crate::client::{
        changes_listener::ChangesListener,
        net::RpcClient,
        provider::{RemoteProvider, StorageDirs, StorageProvider, LocalProvider},
        Result,
    };

    /// Type alias for a file node cache.
    pub type FileCache<W, P> =
        Arc<RwLock<Box<dyn StorageProvider<W, P> + Send + Sync + 'static>>>;

    /// Spawn a change notification listener that
    /// updates the local node cache.
    pub fn spawn_changes_listener<W, P>(
        server: Url, signer: BoxedSigner, cache: FileCache<W, P>) 
    where
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
        server: Url,
        signer: BoxedSigner,
        cache_dir: PathBuf,
        ) -> Result<(FileCache<WalFile, PatchFile>, Address)>
    {
        let address = signer.address()?;
        let client = RpcClient::new(server, signer);
        let dirs = StorageDirs::new(cache_dir, &address.to_string());

        let provider: Box<
            dyn StorageProvider<WalFile, PatchFile>
                + Send
                + Sync
                + 'static,
        > = Box::new(RemoteProvider::new_file_cache(client, dirs)?);

        Ok((Arc::new(RwLock::new(provider)), address))
    }

    /// Create a new local provider.
    pub fn new_local_file_provider(
        signer: BoxedSigner,
        cache_dir: PathBuf) -> Result<(FileCache<WalFile, PatchFile>, Address)>
    {
        let address = signer.address()?;
        let dirs = StorageDirs::new(cache_dir, &address.to_string());

        let provider: Box<
            dyn StorageProvider<WalFile, PatchFile>
                + Send
                + Sync
                + 'static,
        > = Box::new(LocalProvider::new_file_storage(dirs)?);

        Ok((Arc::new(RwLock::new(provider)), address))
    }

    /*
    /// Client that communicates with a single server and
    /// writes it's cache to disc.
    pub struct SpotFileClient<W, P> {
        cache: FileCache<W, P>,
        //changes: ChangesListener,
    }

    impl SpotFileClient<WalFile, PatchFile> {
        /// Create a new SPOT file client.
        pub fn new(
            server: Url,
            signer: BoxedSigner,
            cache_dir: PathBuf,
        ) -> Result<Self> {
            //let changes =
                //ChangesListener::new(server.clone(), signer.clone());

            let address = signer.address()?;
            let client = RpcClient::new(server, signer);
            let dirs = StorageDirs::new(cache_dir, &address.to_string());

            let provider: Box<
                dyn StorageProvider<WalFile, PatchFile>
                    + Send
                    + Sync
                    + 'static,
            > = Box::new(RemoteProvider::new_file_cache(client, dirs)?);
            let cache = Arc::new(RwLock::new(provider));
            Ok(Self { cache })
        }
    }

    impl<W, P> SpotFileClient<W, P>
    where
        W: WalProvider + Send + Sync + 'static,
        P: PatchProvider + Send + Sync + 'static,
    {
        /// Get a clone of the underlying provider.
        pub fn cache(&self) -> FileCache<W, P> {
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
    */
}
