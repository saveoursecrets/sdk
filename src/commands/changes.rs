//! Listen for changes events on the server sent events channel.
use futures::stream::StreamExt;
use sos_net::client::{
    net::changes::{changes, connect},
    provider::ProviderFactory,
};
use sos_sdk::{
    account::AccountRef, mpc::Keypair, signer::ecdsa::BoxedEcdsaSigner,
    url::Url,
};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{helpers::account::sign_in, Result, TARGET};

/// Creates a changes stream and calls handler for every change notification.
async fn changes_stream(
    server: Url,
    server_public_key: Vec<u8>,
    signer: BoxedEcdsaSigner,
    keypair: Keypair,
) -> sos_net::client::Result<()> {
    let (stream, session) = connect(server, server_public_key, signer, keypair).await?;
    let mut stream = changes(stream, Arc::new(Mutex::new(session)));
    while let Some(notification) = stream.next().await {
        let notification = notification?.await?;
        tracing::info!(
            target: TARGET,
            changes = ?notification.changes(),
            vault_id = %notification.vault_id());
    }

    Ok(())
}

/// Start a monitor listening for events on the SSE stream.
pub async fn run(
    server: Url,
    server_public_key: Vec<u8>,
    account: AccountRef) -> Result<()> {
    let (owner, _) = sign_in(&account, ProviderFactory::Local(None)).await?;
    let signer = owner.user.identity().signer().clone();
    let keypair = owner.user.keypair().clone();
    if let Err(e) = changes_stream(
        server, server_public_key, signer, keypair).await {
        tracing::error!(target: TARGET, "{}", e);
        std::process::exit(1);
    }
    Ok(())
}
