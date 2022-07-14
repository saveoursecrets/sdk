//! Listen for changes events on the server sent events channel.
use futures::stream::StreamExt;
use reqwest_eventsource::Event;
use std::path::PathBuf;
use url::Url;

use sos_core::events::ChangeNotification;

use crate::{run_blocking, Result, StdinPassphraseReader};

use sos_node::{Client, ClientBuilder};

async fn changes_stream<F>(client: Client, handler: F) -> sos_node::Result<()>
where
    F: Fn(ChangeNotification) -> (),
{
    let mut es = client.changes().await?;
    while let Some(event) = es.next().await {
        match event {
            Ok(Event::Open) => tracing::debug!("sse connection open"),
            Ok(Event::Message(message)) => {
                let notification: ChangeNotification =
                    serde_json::from_str(&message.data)?;
                handler(notification);
            }
            Err(e) => {
                es.close();
                return Err(e.into());
            }
        }
    }
    Ok(())
}

/// Start a monitor listening for events on the SSE stream.
pub fn monitor(server: Url, keystore: PathBuf) -> Result<()> {
    let reader = StdinPassphraseReader {};
    let client = ClientBuilder::new(server, keystore)
        .with_passphrase_reader(Box::new(reader))
        .build()?;

    let handler = |notification: ChangeNotification| {
        let changes = notification
            .changes()
            .iter()
            .map(|e| format!("{:?}", e))
            .collect::<Vec<_>>();
        tracing::info!(
            changes = ?changes,
            vault_id = %notification.vault_id());
    };

    if let Err(e) = run_blocking(changes_stream(client, handler)) {
        tracing::error!("{}", e);
        std::process::exit(1);
    }
    Ok(())
}
