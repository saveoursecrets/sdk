use sos_net::server::{
    Result, Server, ServerConfig, ServerInfo, State, TransportManager,
};

use axum_server::Handle;
use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};
use tokio::sync::RwLock;

/// Run a web server.
pub async fn run(
    reap_interval: Option<u64>,
    session_duration: Option<u64>,
    bind: String,
    config: PathBuf,
) -> Result<()> {
    let name = env!("CARGO_PKG_NAME").to_string();
    let version = env!("CARGO_PKG_VERSION").to_string();

    let (mut config, keypair) = ServerConfig::load(&config).await?;

    if let Some(reap_interval) = reap_interval {
        config.session.reap_interval = reap_interval;
    }

    if let Some(session_duration) = session_duration {
        config.session.duration = session_duration;
    }

    let transports = TransportManager::new(config.session.duration);

    let backend = config.backend().await?;

    let state = Arc::new(RwLock::new(State {
        info: ServerInfo {
            name,
            version,
            public_key: keypair.public_key().to_owned(),
        },
        keypair,
        config,
        sockets: Default::default(),
        transports,
    }));

    let handle = Handle::new();

    let addr = SocketAddr::from_str(&bind)?;
    let server = Server::new();
    server
        .start(addr, state, Arc::new(RwLock::new(backend)), handle)
        .await?;
    Ok(())
}
