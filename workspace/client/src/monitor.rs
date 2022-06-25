//! Listen for changes events on the server sent events channel.
use futures::stream::StreamExt;
use reqwest_eventsource::Event;
use std::path::PathBuf;
use url::Url;

use sos_core::changes::FeedEvent;

use crate::{run_blocking, Client, ClientBuilder, Result};

async fn stream(client: Client) -> Result<()> {
    let mut es = client.changes().await?;
    while let Some(event) = es.next().await {
        match event {
            Ok(Event::Open) => tracing::debug!("sse connection open"),
            Ok(Event::Message(message)) => {
                let info: FeedEvent = serde_json::from_str(&message.data)?;
                match info {
                    FeedEvent::CreateVault { vault_id, .. } => {
                        tracing::info!(
                            event = %message.event,
                            vault_id = %vault_id);
                    }
                    FeedEvent::UpdateVault {
                        vault_id,
                        change_seq,
                        ..
                    }
                    | FeedEvent::DeleteVault {
                        vault_id,
                        change_seq,
                        ..
                    }
                    | FeedEvent::SetVaultMeta {
                        vault_id,
                        change_seq,
                        ..
                    } => {
                        tracing::info!(
                            event = %message.event,
                            vault_id = %vault_id,
                            change_seq = %change_seq);
                    }
                    FeedEvent::SetVaultName {
                        vault_id,
                        change_seq,
                        name,
                        ..
                    } => {
                        tracing::info!(
                            event = %message.event,
                            vault_id = %vault_id,
                            change_seq = %change_seq,
                            name = %name);
                    }
                    FeedEvent::CreateSecret {
                        vault_id,
                        secret_id,
                        change_seq,
                        ..
                    }
                    | FeedEvent::UpdateSecret {
                        vault_id,
                        secret_id,
                        change_seq,
                        ..
                    }
                    | FeedEvent::DeleteSecret {
                        vault_id,
                        secret_id,
                        change_seq,
                        ..
                    } => {
                        tracing::info!(
                            event = %message.event,
                            vault_id = %vault_id,
                            secret_id = %secret_id,
                            change_seq = %change_seq);
                    }
                }
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
    if let Err(e) = run_blocking(stream(client)) {
        tracing::error!("{}", e);
        std::process::exit(1);
    }
    Ok(())
}
