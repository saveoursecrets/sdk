//! Errors generated by the core library.
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

/// Error thrown by the core library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated when a vault identity byte is wrong.
    #[error("bad identity byte {0}")]
    BadIdentity(u8),

    /// Error generated when a vault algorithm identifier byte is wrong.
    #[error("unknown algorithm {0}")]
    UnknownAlgorithm(u8),

    /// Error generated when a vault algorithm string identifier is wrong.
    #[error("invalid algorithm {0}")]
    InvalidAlgorithm(String),

    /// Error generated when a nonce size is unknown.
    #[error("unknown nonce size {0}")]
    UnknownNonceSize(u8),

    /// Error generated when the kind of a secret is unknown.
    #[error("unknown secret kind {0}")]
    UnknownSecretKind(u8),

    /// Error generated when the kind identifier of an event is unknown.
    #[error("unknown event kind {0}")]
    UnknownEventKind(u16),

    /// Error generated when a file is empty.
    #[error("file {0} is empty")]
    EmptyFile(PathBuf),

    /// Error generated when a file is less than the size of the identity bytes.
    #[error("file {0} is too small, need at least {1} bytes")]
    FileTooSmall(PathBuf, usize),

    /// Error generated when an AeadPack contains a nonce that
    /// is invalid for the decryption algorithm.
    #[error("invalid nonce")]
    InvalidNonce,

    /// Error generated when a vault is locked.
    #[error("vault must be unlocked")]
    VaultLocked,

    /// Error generated when a secret already exists with the given label.
    #[error(
        "secret with the label {0} already exists, labels must be unique"
    )]
    SecretAlreadyExists(String),

    /// Error generated when a secret does not exist for an update operation.
    #[error("secret {0} does not exist")]
    SecretDoesNotExist(Uuid),

    /// Error generated when secret meta data does not exist.
    #[error("too few words for diceware passphrase generation, got {0} but minimum is {1}")]
    DicewareWordsTooFew(usize, u8),

    /// Error generated when a vault has not been initialized (no encrypted meta data).
    #[error("vault is not initialized")]
    VaultNotInit,

    /// Error generated attempting to a initialize a vault when it has already been initialized.
    #[error("vault is already initialized")]
    VaultAlreadyInit,

    /// Error generated when a bip39 word count is invalid.
    #[error("word count must be 12, 18 or 24")]
    InvalidWordCount,

    /// Error generated when the type identifier for a public key is unknown.
    #[error("unknown key type identifier")]
    UnknownKeyTypeId,

    /// Error generated when the leading byte for a compressed public key is invalid.
    #[error(
        "compressed public key has wrong first byte, must be 0x02 0r 0x03"
    )]
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
    #[error(
        "public key is wrong length, expecting {0} bytes but got {1} bytes"
    )]
    InvalidPublicKeyLength(u8, usize),

    /// Error generated when an address has the wrong prefix.
    #[error("address must begin with 0x")]
    BadAddressPrefix,

    /// Error generated when a change sequence overflows `u32::MAX`.
    #[error("too many changes, change sequence number would overflow")]
    TooManyChanges,

    /// Error generated when WAL row data does not match the commit hash.
    #[error("row checksums do not match, expected {commit} but got {value}")]
    HashMismatch {
        /// Expected commit hash.
        commit: String,
        /// Commit hash of the value.
        value: String,
    },

    /// Error generated by password hash.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated by password hash.
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    /// Error generated by password hash.
    #[error(transparent)]
    PasswordHash(#[from] argon2::password_hash::Error),

    /// Error generated parsing integers.
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),

    /// Error generated by the bip39 library.
    #[error(transparent)]
    Bip39(#[from] bip39::Error),

    /// Error generated parsing URLs.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    /// Error generated parsing UUIDs.
    #[error(transparent)]
    Uuid(#[from] uuid::Error),

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated from the binary serializer / deserializer.
    #[error(transparent)]
    Binary(#[from] serde_binary::Error),

    /// Error generated from the binary reader / writer.
    #[error(transparent)]
    BinaryRw(#[from] serde_binary::binary_rw::BinaryError),

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
