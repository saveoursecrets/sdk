use sos_net::{
    sdk::vfs,
    server::{Error, Result, Server, ServerConfig, State},
};

use axum_server::Handle;
use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};
use tokio::sync::RwLock;

/// Initialize default server configuration.
pub async fn init(path: PathBuf) -> Result<()> {
    if vfs::try_exists(&path).await? {
        return Err(Error::FileExists(path));
    }

    let config: ServerConfig = Default::default();
    let content = toml::to_string_pretty(&config)?;
    vfs::write(path, content.as_bytes()).await?;
    Ok(())
}

/// Run a web server.
pub async fn run(bind: String, config: PathBuf) -> Result<()> {
    let config = ServerConfig::load(&config).await?;
    let backend = config.backend().await?;

    let state = Arc::new(RwLock::new(State {
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
