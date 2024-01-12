//! Listen for changes events on the server sent events channel.
use futures::stream::StreamExt;
use sos_net::{
    client::{changes, connect, HostedOrigin},
    sdk::{
        hex,
        identity::AccountRef,
        signer::{ecdsa::BoxedEcdsaSigner, ed25519::BoxedEd25519Signer},
        url::Url,
    },
};

use crate::{helpers::account::sign_in, Result, TARGET};

/// Creates a changes stream and calls handler for every change notification.
async fn changes_stream(
    url: Url,
    public_key: Vec<u8>,
    signer: BoxedEcdsaSigner,
    device: BoxedEd25519Signer,
) -> sos_net::client::Result<()> {
    let name = hex::encode(&public_key);
    let origin = HostedOrigin {
        url,
        public_key,
        name,
    };

    let (stream, client) = connect(origin, signer, device).await?;
    let mut stream = changes(stream, client);
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
    account: AccountRef,
) -> Result<()> {
    let (owner, _) = sign_in(&account).await?;
    let signer = owner.user()?.identity()?.signer().clone();
    let device = owner.user()?.identity()?.device().clone();
    if let Err(e) = changes_stream(
        server,
        server_public_key,
        signer,
        device.into(),
    )
    .await
    {
        tracing::error!(target: TARGET, "{}", e);
        std::process::exit(1);
    }
    Ok(())
}
