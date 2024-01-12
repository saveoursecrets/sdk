use sos_net::server::{Result, Server, ServerConfig, ServerInfo, State};

use axum_server::Handle;
use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};
use tokio::sync::RwLock;

/// Run a web server.
pub async fn run(bind: String, config: PathBuf) -> Result<()> {
    let name = env!("CARGO_PKG_NAME").to_string();
    let version = env!("CARGO_PKG_VERSION").to_string();

    let config = ServerConfig::load(&config).await?;
    let backend = config.backend().await?;

    let state = Arc::new(RwLock::new(State {
        info: ServerInfo { name, version },
        config,
        sockets: Default::default(),
    }));

    let handle = Handle::new();

    let addr = SocketAddr::from_str(&bind)?;
    let server = Server::new();
    server
        .start(addr, state, Arc::new(RwLock::new(backend)), handle)
        .await?;
    Ok(())
}
