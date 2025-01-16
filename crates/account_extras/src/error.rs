use thiserror::Error;

/// Error type for the account extras library.
#[derive(Debug, Error)]
pub enum Error {
    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Errors generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Errors generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Errors generated by the vault library.
    #[error(transparent)]
    Vault(#[from] sos_vault::Error),

    /// Errors generated by the database storage.
    #[error(transparent)]
    DatabaseStorage(#[from] sos_database::StorageError),
}
