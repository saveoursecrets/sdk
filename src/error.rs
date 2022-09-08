use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /*
    #[error("subcommand is required")]
    CommandRequired,

    #[error("{0} is not a known command")]
    UnknownCommand(String),
    */
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
