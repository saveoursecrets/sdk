//! Listen for changes events on the server sent events channel.
use futures::stream::StreamExt;
use sos_net::client::{
    net::changes::{changes, connect},
    provider::ProviderFactory,
};
use sos_sdk::{
    account::AccountRef, signer::ecdsa::BoxedEcdsaSigner, url::Url,
};

use crate::{helpers::account::sign_in, Result, TARGET};

/// Creates a changes stream and calls handler for every change notification.
async fn changes_stream(
    server: Url,
    signer: BoxedEcdsaSigner,
) -> sos_net::client::Result<()> {
    let (stream, session) = connect(server, signer).await?;
    let mut stream = changes(stream, session);
    while let Some(notification) = stream.next().await {
        let notification = notification?;
        tracing::info!(
            target: TARGET,
            changes = ?notification.changes(),
            vault_id = %notification.vault_id());
    }

    Ok(())
}

/// Start a monitor listening for events on the SSE stream.
pub async fn run(server: Url, account: AccountRef) -> Result<()> {
    let (owner, _) = sign_in(&account, ProviderFactory::Local).await?;
    let signer = owner.user.identity().signer().clone();
    if let Err(e) = changes_stream(server, signer).await {
        tracing::error!(target: TARGET, "{}", e);
        std::process::exit(1);
    }
    Ok(())
}
