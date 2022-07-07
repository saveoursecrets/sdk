//! Listen for changes events on the server sent events channel.
use futures::stream::StreamExt;
use reqwest_eventsource::Event;
use std::path::PathBuf;
use url::Url;

use sos_core::events::ChangeNotification;

use crate::{run_blocking, Client, ClientBuilder, Result};

async fn stream(client: &Client) -> Result<()> {
    let mut es = client.changes().await?;
    while let Some(event) = es.next().await {
        match event {
            Ok(Event::Open) => tracing::debug!("sse connection open"),
            Ok(Event::Message(message)) => {
                let notification: ChangeNotification =
                    serde_json::from_str(&message.data)?;
                let changes = notification
                    .changes()
                    .iter()
                    .map(|e| format!("{:?}", e))
                    .collect::<Vec<_>>();
                tracing::info!(
                    changes = ?changes,
                    vault_id = %notification.vault_id());
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
    let client = ClientBuilder::new(server, keystore).build()?;
    if let Err(e) = run_blocking(stream(&client)) {
        tracing::error!("{}", e);
        std::process::exit(1);
    }
    Ok(())
}
