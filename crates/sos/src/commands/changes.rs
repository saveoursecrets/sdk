//! Listen for changes events on the server sent events channel.
use futures::stream::StreamExt;
use sos_net::{
    client::{changes, connect, Origin},
    sdk::{
        hex,
        identity::AccountRef,
        signer::{ecdsa::BoxedEcdsaSigner, ed25519::BoxedEd25519Signer},
        url::Url,
    },
};

use crate::{
    helpers::{
        account::sign_in,
        messages::{fail, info},
    },
    Result,
};

/// Creates a changes stream and calls handler for every change notification.
async fn changes_stream(
    url: Url,
    public_key: Vec<u8>,
    signer: BoxedEcdsaSigner,
    device: BoxedEd25519Signer,
) -> sos_net::client::Result<()> {
    let name = hex::encode(&public_key);
    let origin = Origin {
        url,
        public_key,
        name,
    };

    let (stream, client) = connect(origin, signer, device).await?;
    let mut stream = changes(stream, client);
    while let Some(notification) = stream.next().await {
        let notification = notification?.await?;
        info(format!(
            "{:#?} {}"
            notification.changes(),
            notification.vault_id()));
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
    if let Err(e) =
        changes_stream(server, server_public_key, signer, device.into()).await
    {
        fail(e.to_string());
        std::process::exit(1);
    }
    Ok(())
}
