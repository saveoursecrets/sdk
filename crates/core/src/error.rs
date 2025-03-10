//! Errors generated by the core library.
use thiserror::Error;

use crate::VaultId;

/// Error thrown by the core library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated when a commit tree is expected to have a root.
    #[error("commit tree does not have a root")]
    NoRootCommit,

    /// Error generated when a commit tree is expected to have a last commit.
    #[error("commit tree does not have a last commit")]
    NoLastCommit,

    /// Error generated when an external file could not be parsed.
    #[error("external file reference '{0}' could not be parsed")]
    InvalidExternalFile(String),

    /// Error generated when the kind identifier of an event is unknown.
    #[error("unknown event kind {0}")]
    UnknownEventKind(u16),

    /// Error generated when the kind identifier of an event is unknown.
    #[error("unknown event type {0}")]
    UnknownEventType(String),

    /// Error generated when attempting to use an asymmetric
    /// private key with a symmetric cipher.
    #[error("symmetric private key required for symmetric cipher")]
    NotSymmetric,

    /// Error generated when attempting to use a symmetric
    /// private key with an asymmetric cipher.
    #[error("asymmetric private key required for asymmetric cipher")]
    NotAsymmetric,

    /// Error generated when a vault cipher string identifier is wrong.
    #[error("invalid cipher {0}")]
    InvalidCipher(String),

    /// Error generated when an AeadPack contains a nonce that
    /// is invalid for the decryption cipher.
    #[error("invalid nonce")]
    InvalidNonce,

    /// Error generated when a vault key derivation function string
    /// identifier is wrong.
    #[error("invalid key derivation function {0}")]
    InvalidKeyDerivation(String),

    /// Error generated when an account identififer has
    /// the wrong prefix.
    #[error("account identifier must begin with 0x")]
    BadAccountIdPrefix,

    /// Error generated when a vault identity byte is wrong.
    #[error("bad identity byte {0:#04x} at position {1} expecting {2}")]
    BadIdentity(u8, usize, String),

    /// Error generated when a buffer used to read identity bytes
    /// is not long enough.
    #[error("buffer passed for identity check is too short")]
    IdentityLength,

    /// Error generated when a a event log file does
    /// not begin with a create vault event.
    #[error("first record in an event log must be a create vault event")]
    CreateEventMustBeFirst,

    /// Error generated when a event log create vault event is not the first record.
    #[error("event log create vault event must only be the first record")]
    CreateEventOnlyFirst,

    /// Generic boxed error.
    #[error(transparent)]
    Boxed(#[from] Box<dyn std::error::Error + Send + Sync>),

    /// Error generated converting by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Authentication errors.
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),

    /// Error generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Error generated by the Base58 library.
    #[error(transparent)]
    Base58(#[from] bs58::encode::Error),

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated converting from hexadecimal.
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    /// Error generated converting from UUID.
    #[error(transparent)]
    Uuid(#[from] uuid::Error),

    /// Error generated converting time types.
    #[error(transparent)]
    Time(#[from] time::error::ComponentRange),

    /// Error generated formatting time.
    #[error(transparent)]
    TimeFormat(#[from] time::error::Format),

    /// Error generated parsing time.
    #[error(transparent)]
    TimeParse(#[from] time::error::Parse),

    /// Error generated creating format descriptions for date formatting.
    #[error(transparent)]
    InvalidFormat(#[from] time::error::InvalidFormatDescription),

    /// Error generated by the SHA2 library.
    #[error(transparent)]
    Sha2DigestLength(#[from] sha2::digest::InvalidLength),

    /// Error generated parsing PEM files.
    #[error(transparent)]
    Pem(#[from] pem::PemError),

    /// Error generated by the crypto library.
    #[error(transparent)]
    ChaCha(#[from] chacha20poly1305::Error),

    /// Error generated by password hash.
    #[error(transparent)]
    PasswordHash(#[from] argon2::password_hash::Error),

    /// Error generated by the AGE library when encrypting.
    #[error(transparent)]
    AgeEncrypt(#[from] age::EncryptError),

    /// Error generated by the AGE library when decrypting.
    #[error(transparent)]
    AgeDecrypt(#[from] age::DecryptError),
}

/// Extension functions for error types.
pub trait ErrorExt {
    /// Whether this is a secret not found error.
    fn is_secret_not_found(&self) -> bool;

    /// Whether this is a permission denied error.
    fn is_permission_denied(&self) -> bool;

    /// Whether authentication is required.
    fn is_forbidden(&self) -> bool;
}

/// Storage error shared between the client and server.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Error generated attempting to access a folder
    /// that is not available in-memory.
    #[error("folder not found '{0}'")]
    FolderNotFound(VaultId),
}

/// Authentication errors.
#[derive(Debug, Error)]
pub enum AuthenticationError {
    /// Error generated accessing an account that is not
    /// authenticated when authentication is required.
    #[error("account not authenticated, sign in required")]
    NotAuthenticated,

    /// Error generated when attempting to verify a password fails.
    ///
    /// This can happen when unlocking a vault or verifying a password.
    #[error("password verification failed")]
    PasswordVerification,
}
