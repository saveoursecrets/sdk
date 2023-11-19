//! Storage provider trait.

use async_trait::async_trait;

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use sos_sdk::{
    account::{AccountStatus, ImportedAccount, NewAccount},
    commit::{
        CommitHash, CommitProof, CommitRelationship, CommitTree, SyncInfo,
    },
    constants::{EVENT_LOG_EXT, VAULT_EXT},
    crypto::{AccessKey, KeyDerivation, PrivateKey},
    decode, encode,
    events::{
        AuditEvent, AuditLogFile, ChangeAction, ChangeNotification, Event,
        EventKind, EventLogFile, ReadEvent, WriteEvent,
    },
    mpc::Keypair,
    passwd::ChangePassword,
    search::SearchIndex,
    signer::ecdsa::{Address, BoxedEcdsaSigner},
    storage::{AppPaths, UserPaths},
    url::Url,
    vault::{
        secret::{Secret, SecretData, SecretId, SecretMeta},
        Gatekeeper, Header, Summary, Vault, VaultId,
    },
    vfs, Timestamp,
};

use tokio::sync::RwLock;

use sos_sdk::account::RestoreTargets;

use crate::client::{
    net::RpcClient, user::Origin, Error, RemoteSync, Result,
};

/// Create a new remote provider.
pub async fn new_remote_provider(
    origin: &Origin,
    signer: BoxedEcdsaSigner,
    keypair: Keypair,
) -> Result<(RemoteProvider, Address)> {
    let (local, address) = new_local_provider(signer.clone(), None).await?;
    let client = RpcClient::new(
        origin.url.clone(),
        origin.public_key.clone(),
        signer,
        keypair,
    )?;
    Ok((
        RemoteProvider::new(Arc::new(RwLock::new(local)), client),
        address,
    ))
}

/// Create a new local provider.
pub async fn new_local_provider(
    signer: BoxedEcdsaSigner,
    data_dir: Option<PathBuf>,
) -> Result<(LocalProvider, Address)> {
    let data_dir = if let Some(data_dir) = data_dir {
        data_dir
    } else {
        AppPaths::data_dir().map_err(|_| Error::NoCache)?
    };

    let address = signer.address()?;
    let dirs = UserPaths::new(data_dir, &address.to_string());
    Ok((LocalProvider::new(dirs).await?, address))
}

pub(crate) fn assert_proofs_eq(
    client_proof: &CommitProof,
    server_proof: &CommitProof,
) -> Result<()> {
    if client_proof.root != server_proof.root {
        let client = CommitHash(client_proof.root);
        let server = CommitHash(server_proof.root);
        Err(Error::RootHashMismatch(client, server))
    } else {
        Ok(())
    }
}

mod local_provider;
mod macros;
mod remote_provider;
mod state;
//mod sync;

pub use local_provider::LocalProvider;
pub use remote_provider::RemoteProvider;

pub use state::ProviderState;

/// Spawn a change notification listener that
/// updates the local node cache.
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn_changes_listener(
    server: Url,
    server_public_key: Vec<u8>,
    signer: BoxedEcdsaSigner,
    keypair: Keypair,
    cache: Arc<RwLock<LocalProvider>>,
) {
    use crate::client::changes_listener::ChangesListener;
    let listener =
        ChangesListener::new(server, server_public_key, signer, keypair);
    listener.spawn(move |notification| {
        let cache = Arc::clone(&cache);
        async move {
            //println!("{:#?}", notification);
            let mut writer = cache.write().await;
            todo!("restore handling change event notifications");
            //let _ = writer.handle_change(notification).await;
        }
    });
}
