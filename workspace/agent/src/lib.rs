use sos_node::agent::{default_path, server::KeyAgentServer};
use std::process::{Command, Stdio};

mod error;

pub type Result<T> = std::result::Result<T, error::Error>;

pub use error::Error;

pub const ENV: &str = "SOS_AGENT_SOCKET";

/// Start the agent service listening on the socket.
pub async fn listen(socket_path: String) -> Result<()> {
    let server = KeyAgentServer::new(socket_path)?;
    server.run().await?;
    Ok(())
}

/// Spawn a key agent service.
pub fn spawn() -> Result<()> {
    let cmd = if cfg!(debug_assertions) {
        "cargo"
    } else {
        "sos-agent"
    };

    let args = if cfg!(debug_assertions) {
        vec!["run"]
    } else {
        vec![]
    };

    let path = default_path().ok_or(Error::NoCache)?;
    if path.exists() {
        return Err(Error::SocketExists(path));
    }

    let child = Command::new(cmd)
        .args(args)
        .env(ENV, path.to_string_lossy().as_ref())
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .spawn()?;
    tracing::info!("agent pid {}", child.id());
    Ok(())
}
