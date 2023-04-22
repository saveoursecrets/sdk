//! Listen for changes events on the server sent events channel.
use futures::stream::StreamExt;
use sos_core::{signer::ecdsa::BoxedEcdsaSigner, url::Url};
use sos_node::client::{
    net::changes::{changes, connect},
    run_blocking,
};

use crate::helpers::account::sign_in;
use crate::Result;

/// Creates a changes stream and calls handler for every change notification.
async fn changes_stream(
    server: Url,
    signer: BoxedEcdsaSigner,
) -> sos_node::client::Result<()> {
    let (stream, session) = connect(server, signer).await?;
    let mut stream = changes(stream, session);

    while let Some(notification) = stream.next().await {
        let notification = notification?;
        tracing::info!(
            changes = ?notification.changes(),
            vault_id = %notification.vault_id());
    }

    Ok(())
}

/// Start a monitor listening for events on the SSE stream.
pub fn monitor(server: Url, account_name: String) -> Result<()> {
    let (_, user, _, _, _) = sign_in(&account_name)?;
    let signer = user.signer;
    if let Err(e) = run_blocking(changes_stream(server, signer)) {
        tracing::error!("{}", e);
        std::process::exit(1);
    }
    Ok(())
}
