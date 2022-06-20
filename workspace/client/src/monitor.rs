use futures::stream::StreamExt;
use reqwest_eventsource::Event;
use serde_json::Value;
use std::path::PathBuf;
use url::Url;

use crate::{run_blocking, Client, ClientBuilder, Result};

async fn stream(client: Client) -> Result<()> {
    let mut es = client.changes().await?;
    while let Some(event) = es.next().await {
        match event {
            Ok(Event::Open) => {
                tracing::debug!("sse connection open");
            }
            Ok(Event::Message(message)) => {
                let data: Value = serde_json::from_str(&message.data)?;
                tracing::info!(event = %message.event, "{:?}", data);
            }
            Err(e) => {
                println!("Error: {}", e);
                es.close();
            }
        }
    }
    Ok(())
}

/// Start a monitor listening for events on the SSE stream.
pub fn monitor(server: Url, keystore: PathBuf) -> Result<()> {
    let builder = ClientBuilder::new(server, keystore);
    let client = builder.build()?;
    Ok(run_blocking(stream(client))?)
}
