//! Listen for changes events on the server sent events channel.
use std::path::PathBuf;
use url::Url;

use crate::{Result, StdinPassphraseReader};
use futures::stream::StreamExt;
use sos_node::client::{net::RequestClient, run_blocking, ClientBuilder};

/// Creates a changes stream and calls handler for every change notification.
async fn changes_stream(
    client: &RequestClient,
) -> sos_node::client::Result<()> {
    let mut es = client.changes().await?;
    while let Some(notification) = es.next().await {
        let notification = notification?;
        tracing::info!(
            changes = ?notification.changes(),
            vault_id = %notification.vault_id());
    }
    Ok(())
}

/// Start a monitor listening for events on the SSE stream.
pub fn monitor(server: Url, keystore: PathBuf) -> Result<()> {
    let reader = StdinPassphraseReader {};
    let client = ClientBuilder::new(server, keystore)
        .with_passphrase_reader(Box::new(reader))
        .build()?;

    if let Err(e) = run_blocking(changes_stream(&client)) {
        tracing::error!("{}", e);
        std::process::exit(1);
    }
    Ok(())
}
