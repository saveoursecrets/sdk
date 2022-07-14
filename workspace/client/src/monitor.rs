//! Listen for changes events on the server sent events channel.
use std::path::PathBuf;
use url::Url;

use crate::{Result, StdinPassphraseReader};
use sos_core::events::ChangeNotification;
use sos_node::{client::changes_stream, run_blocking, ClientBuilder};

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

    if let Err(e) = run_blocking(changes_stream(&client, handler)) {
        tracing::error!("{}", e);
        std::process::exit(1);
    }
    Ok(())
}
