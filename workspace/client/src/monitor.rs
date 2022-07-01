//! Listen for changes events on the server sent events channel.
use futures::stream::StreamExt;
use reqwest_eventsource::Event;
use std::path::PathBuf;
use url::Url;

use sos_core::events::ChangeEvent;

use crate::{run_blocking, Client, ClientBuilder, Result};

async fn stream(client: Client) -> Result<()> {
    let mut es = client.changes().await?;
    while let Some(event) = es.next().await {
        match event {
            Ok(Event::Open) => tracing::debug!("sse connection open"),
            Ok(Event::Message(message)) => {
                let info: ChangeEvent = serde_json::from_str(&message.data)?;
                match info {
                    ChangeEvent::CreateVault { vault_id, .. } => {
                        tracing::info!(
                            event = %message.event,
                            vault_id = %vault_id);
                    }
                    ChangeEvent::UpdateVault { vault_id, .. }
                    | ChangeEvent::DeleteVault { vault_id, .. }
                    | ChangeEvent::SetVaultMeta { vault_id, .. } => {
                        tracing::info!(
                            event = %message.event,
                            vault_id = %vault_id);
                    }
                    ChangeEvent::SetVaultName { vault_id, name, .. } => {
                        tracing::info!(
                            event = %message.event,
                            vault_id = %vault_id,
                            name = %name);
                    }
                    ChangeEvent::CreateSecret {
                        vault_id,
                        secret_id,
                        ..
                    }
                    | ChangeEvent::UpdateSecret {
                        vault_id,
                        secret_id,
                        ..
                    }
                    | ChangeEvent::DeleteSecret {
                        vault_id,
                        secret_id,
                        ..
                    } => {
                        tracing::info!(
                            event = %message.event,
                            vault_id = %vault_id,
                            secret_id = %secret_id);
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
