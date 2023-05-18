//! Memory provider that communicates with a remote server.
//!
//! Uses static futures so they can be driven from webassembly.
use crate::client::{
    net::RpcClient,
    provider::{ArcProvider, ProviderFactory},
    Error, Result,
};
use secrecy::SecretString;
use sos_sdk::{
    commit::SyncInfo,
    events::{ChangeAction, ChangeNotification, SyncEvent},
    signer::ecdsa::BoxedEcdsaSigner,
    vault::{
        secret::{Secret, SecretData, SecretId, SecretMeta},
        Summary, Vault,
    },
};
use std::{collections::HashSet, future::Future, sync::Arc};
use tokio::sync::RwLock;
use url::Url;

/// Client that communicates with a single server and
/// writes it's cache to memory.
///
/// Uses static futures so that it can be used in webassembly.
pub struct MemoryProvider {
    provider: ArcProvider,
    url: Url,
    signer: BoxedEcdsaSigner,
}

impl MemoryProvider {
    /// Create a new SPOT memory client.
    pub fn new(server: Url, signer: BoxedEcdsaSigner) -> Result<Self> {
        let url = server.clone();
        let client_signer = signer.clone();
        let factory = ProviderFactory::Memory(Some(server.clone()));
        let (provider, _) = factory.create_provider(signer)?;
        let provider = Arc::new(RwLock::new(provider));
        Ok(Self {
            url,
            signer: client_signer,
            provider,
        })
    }

    /// Get the URL of the remote node.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Get the signer.
    pub fn signer(&self) -> &BoxedEcdsaSigner {
        &self.signer
    }

    /// Create a new client.
    ///
    /// Exposed so that the webassembly bindings may
    /// use a client to get a valid URL to use for listening to
    /// change notifications. The generated URL then needs to be
    /// sent to Javascript so it can create a websocket connection.
    pub fn new_client(&self) -> RpcClient {
        RpcClient::new(self.url.clone(), self.signer.clone())
    }

    /// Get a clone of the underlying provider.
    pub fn provider(&self) -> ArcProvider {
        Arc::clone(&self.provider)
    }

    /// Authenticate for a session.
    pub fn authenticate(
        cache: ArcProvider,
    ) -> impl Future<Output = Result<()>> + 'static {
        async move {
            let mut writer = cache.write().await;
            writer.authenticate().await?;
            Ok::<(), Error>(())
        }
    }

    /// Create an account.
    pub fn create_account(
        cache: ArcProvider,
        buffer: Vec<u8>,
    ) -> impl Future<Output = Result<Summary>> + 'static {
        async move {
            let mut writer = cache.write().await;
            let summary = writer.create_account_with_buffer(buffer).await?;
            Ok(summary)
        }
    }

    /// List the vaults.
    pub fn list_vaults(
        cache: ArcProvider,
    ) -> impl Future<Output = Result<Vec<Summary>>> + 'static {
        async move {
            let mut writer = cache.write().await;
            let vaults = writer.load_vaults().await?;
            Ok::<Vec<Summary>, Error>(vaults.to_vec())
        }
    }

    /// Create a vault.
    pub fn create_vault(
        cache: ArcProvider,
        name: String,
        passphrase: SecretString,
    ) -> impl Future<Output = Result<Summary>> + 'static {
        async move {
            let mut writer = cache.write().await;
            let (_, summary) =
                writer.create_vault(name, Some(passphrase)).await?;
            Ok::<Summary, Error>(summary)
        }
    }

    /// Remove a vault.
    pub fn remove_vault(
        cache: ArcProvider,
        summary: Summary,
    ) -> impl Future<Output = Result<()>> + 'static {
        async move {
            let mut writer = cache.write().await;
            writer.remove_vault(&summary).await?;
            Ok::<(), Error>(())
        }
    }

    /// Pull a vault.
    pub fn pull(
        cache: ArcProvider,
        summary: Summary,
        force: bool,
    ) -> impl Future<Output = Result<SyncInfo>> + 'static {
        async move {
            let mut writer = cache.write().await;
            let info = writer.pull(&summary, force).await?;
            Ok::<SyncInfo, Error>(info)
        }
    }

    /// Change the password for a vault.
    pub fn change_password(
        cache: ArcProvider,
        vault: Vault,
        current_passphrase: SecretString,
        new_passphrase: SecretString,
    ) -> impl Future<Output = Result<()>> + 'static {
        async move {
            let mut writer = cache.write().await;
            writer
                .change_password(&vault, current_passphrase, new_passphrase)
                .await?;
            Ok::<(), Error>(())
        }
    }

    /// Rename a vault.
    pub fn rename_vault(
        cache: ArcProvider,
        summary: Summary,
        name: String,
    ) -> impl Future<Output = Result<()>> + 'static {
        async move {
            let mut writer = cache.write().await;
            writer.set_vault_name(&summary, &name).await?;
            Ok::<(), Error>(())
        }
    }

    /// Patch a vault.
    pub fn patch(
        cache: ArcProvider,
        summary: Summary,
        events: Vec<SyncEvent<'static>>,
    ) -> impl Future<Output = Result<()>> + 'static {
        async move {
            let mut writer = cache.write().await;
            writer.patch(&summary, events).await?;
            Ok::<(), Error>(())
        }
    }

    /// Handle a change notification.
    pub fn handle_change(
        cache: ArcProvider,
        change: ChangeNotification,
    ) -> impl Future<Output = Result<(bool, HashSet<ChangeAction>)>> + 'static
    {
        async move {
            let mut writer = cache.write().await;
            let result = writer.handle_change(change).await?;
            Ok::<_, Error>(result)
        }
    }

    /// Create a secret in the currently open vault.
    pub fn create_secret(
        cache: ArcProvider,
        meta: SecretMeta,
        secret: Secret,
    ) -> impl Future<Output = Result<SyncEvent<'static>>> + 'static {
        async move {
            let mut writer = cache.write().await;
            let event = writer.create_secret(meta, secret).await?;
            Ok::<_, Error>(event.into_owned())
        }
    }

    /// Read a secret in the currently open vault.
    pub fn read_secret(
        cache: ArcProvider,
        id: SecretId,
    ) -> impl Future<Output = Result<(SecretMeta, Secret, SyncEvent<'static>)>>
           + 'static {
        async move {
            let mut writer = cache.write().await;
            let (meta, secret, event) = writer.read_secret(&id).await?;
            let event = event.into_owned();
            Ok::<_, Error>((meta, secret, event))
        }
    }

    /// Update a secret in the currently open vault.
    pub fn update_secret(
        cache: ArcProvider,
        id: SecretId,
        meta: SecretMeta,
        secret: Secret,
    ) -> impl Future<Output = Result<SyncEvent<'static>>> + 'static {
        async move {
            let mut writer = cache.write().await;
            let secret_data = SecretData {
                id: Some(id),
                meta,
                secret,
            };
            let event = writer.update_secret(&id, secret_data).await?;
            Ok::<_, Error>(event.into_owned())
        }
    }

    /// Delete a secret in the currently open vault.
    pub fn delete_secret(
        cache: ArcProvider,
        id: SecretId,
    ) -> impl Future<Output = Result<SyncEvent<'static>>> + 'static {
        async move {
            let mut writer = cache.write().await;
            let event = writer.delete_secret(&id).await?;
            Ok::<_, Error>(event.into_owned())
        }
    }
}
