//! Errors generated by the core library.
use thiserror::Error;

/// Error thrown by the core library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated when a vault identity byte is wrong.
    #[error("bad identity byte {0}")]
    BadIdentity(u8),

    /// Error generated when the kind of a secret is unknown.
    #[error("unknown secret kind {0}")]
    UnknownSecretKind(u8),

    /// Error generated when a vault is locked.
    #[error("vault must be unlocked")]
    VaultLocked,

    /// Error generated when a secret does not exist.
    #[error("secret {0} does not exist")]
    SecretDoesNotExist(uuid::Uuid),

    /// Error generated when secret meta data does not exist.
    #[error("secret meta data for {0} does not exist")]
    SecretMetaDoesNotExist(uuid::Uuid),

    /// Error generated when a vault has not been initialized (no encrypted meta data).
    #[error("vault is not initialized")]
    VaultNotInit,

    /// Error generated when a bip39 word count is invalid.
    #[error("word count must be 12, 18 or 24")]
    InvalidWordCount,

    /// Error generated when the type identifier for a public key is unknown.
    #[error("unknown key type identifier")]
    UnknownKeyTypeId,

    /// Error generated when the leading byte for a compressed public key is invalid.
    #[error("compressed public key has wrong first byte, must be 0x02 0r 0x03")]
    BadPublicKeyByte,

    /// Error generated when a public key is not compressed.
    #[error("not a compressed public key")]
    NotCompressedPublicKey,

    /// Error generated when a response to a challenge is invalid.
    #[error("invalid challenge response")]
    InvalidChallengeResponse,

    /// Error generated when a challenge could not be found.
    #[error("challenge not found")]
    ChallengeNotFound,

    /// Error generated when a public key has the wrong length.
    #[error("public key is wrong length, expecting {0} bytes but got {1} bytes")]
    InvalidPublicKeyLength(u8, usize),

    /// Error generated parsing integers.
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),

    /// Error generated by the bip39 library.
    #[error(transparent)]
    Bip39(#[from] bip39::Error),

    /// Error generated by the JWT library.
    #[error(transparent)]
    Jwt(#[from] jwt_simple::Error),

    /// Error generated parsing URLs.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    /// Error generated parsing UUIDs.
    #[error(transparent)]
    Uuid(#[from] uuid::Error),

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated from the binary reader / writer.
    #[error(transparent)]
    Binary(#[from] binary_rw::BinaryError),

    /// Error generated whilst reading or writing to a binary stream.
    #[error(transparent)]
    BinaryStream(#[from] binary_rw::StreamError),

    /// Error generated during AES encryption and decryption.
    #[error(transparent)]
    Aes(#[from] aes_gcm::Error),

    /// Error generated by the ECDSA library.
    #[error(transparent)]
    Ecdsa(#[from] k256::ecdsa::Error),

    /// Error generated by elliptic curve library.
    #[error(transparent)]
    Elliptic(#[from] k256::elliptic_curve::Error),
}
