use thiserror::Error;

/// Errors generated by the library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated when a vault has not
    /// been initialized (no encrypted meta data).
    #[error("vault is not initialized")]
    VaultNotInit,

    /// Error generated when a vault is locked.
    #[error("vault must be unlocked")]
    VaultLocked,

    /// Error generated when attempting to verify a password fails.
    ///
    /// This can happen when calling `verify()` on a `Vault` or `unlock()`
    /// on a `Gatekeeper`.
    #[error("password verification failed")]
    PassphraseVerification,

    /// Permission denied.
    ///
    /// If a shared vault is set to private shared access and
    /// somebody other than the owner attempts to write to encrypt
    /// a shared entry this error is generated.
    #[error("permission denied")]
    PermissionDenied,

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Errors generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Errors generated by the vault library.
    #[error(transparent)]
    Vault(#[from] sos_vault::Error),

    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
