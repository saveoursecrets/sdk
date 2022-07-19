//! Listen for changes events on the server sent events channel.
use std::path::PathBuf;
use url::Url;

use crate::{Result, StdinPassphraseReader};
use futures::stream::StreamExt;
use sos_core::signer::Signer;
use sos_node::client::{
    net::{changes::ChangeStreamEvent, RequestClient},
    run_blocking, ClientBuilder,
};

/// Creates a changes stream and calls handler for every change notification.
async fn changes_stream<S>(
    client: &RequestClient<S>,
) -> sos_node::client::Result<()>
where
    S: Signer + Send + Sync + 'static,
{
    let mut es = client.changes().await?;
    while let Some(event) = es.next().await {
        let event = event?;
        match event {
            ChangeStreamEvent::Message(notification) => {
                tracing::info!(
                    changes = ?notification.changes(),
                    vault_id = %notification.vault_id());
            }
            _ => {}
        }
    }
    Ok(())
}

/// Start a monitor listening for events on the SSE stream.
pub fn monitor(server: Url, keystore: PathBuf) -> Result<()> {
    let reader = StdinPassphraseReader {};
    let client = ClientBuilder::new(server, keystore)
        .with_passphrase_reader(Box::new(reader))
        .with_use_agent(true)
        .build()?;

    if let Err(e) = run_blocking(changes_stream(&client)) {
        tracing::error!("{}", e);
        std::process::exit(1);
    }
    Ok(())
}
