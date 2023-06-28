use sos_net::{
    server::{
        BackendHandler, Result, Server, ServerConfig, ServerInfo, State,
    },
    FileLocks,
};
use sos_sdk::{
    crypto::channel::{ServerTransportManager, SessionManager},
    events::AuditLogFile,
};

use axum_server::Handle;
use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};
use tokio::sync::RwLock;

use crate::TARGET;

/// Run a web server.
pub async fn run(
    audit_log: Option<PathBuf>,
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

    let sessions = SessionManager::new(config.session.duration);
    let transports = ServerTransportManager::new(config.session.duration);

    //println!("Config {:#?}", config);

    let mut backend = config.backend().await?;

    let audit_log_file = audit_log.unwrap_or_else(|| config.audit_file());

    let mut locks = FileLocks::new();
    locks.add(&audit_log_file)?;
    // Move into the backend so it can manage lock files too
    backend.handler_mut().set_file_locks(locks)?;

    tracing::debug!(
        target: TARGET,
        "lock files {:#?}",
        backend.handler().file_locks().paths()
    );

    // Set up the audit log
    let audit_log = AuditLogFile::new(&audit_log_file).await?;

    let state = Arc::new(RwLock::new(State {
        keypair,
        info: ServerInfo { name, version },
        config,
        backend,
        audit_log,
        sockets: Default::default(),
        transports,
        sessions,
    }));

    let handle = Handle::new();

    let addr = SocketAddr::from_str(&bind)?;
    let server = Server::new();
    server.start(addr, state, handle).await?;
    Ok(())
}
