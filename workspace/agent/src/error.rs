use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("unable to determine cache directory")]
    NoCache,

    #[error(
        "socket file {0} already exists, maybe the agent is already running?"
    )]
    SocketExists(PathBuf),

    #[error(transparent)]
    Agent(#[from] sos_node::agent::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
