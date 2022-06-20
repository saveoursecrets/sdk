use futures::stream::StreamExt;
use reqwest_eventsource::Event;
use std::path::PathBuf;
use url::Url;

use crate::{run_blocking, Client, ClientBuilder, Result};

async fn stream(client: Client) -> Result<()> {
    let mut es = client.changes().await?;
    while let Some(event) = es.next().await {
        match event {
            Ok(Event::Open) => println!("Connection Open!"),
            Ok(Event::Message(message)) => println!("Message: {:#?}", message),
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
