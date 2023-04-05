//! Errors generated by the core library.
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

/// Error thrown by the core library.
#[derive(Debug, Error)]
pub enum Error {
    /// Generic error message variant.
    #[error("{0}")]
    Message(String),

    /// Error generated when a directory is expected.
    #[error("path {0} is not a directory")]
    NotDirectory(PathBuf),

    /// Error generated attempting acquire a lock on a file that is already locked.
    #[error("file {0} is already locked")]
    FileLocked(PathBuf),

    /// Error generated when a vault identity byte is wrong.
    #[error("bad identity byte {0}")]
    BadIdentity(u8),

    /// Error generated when a buffer used to read identity bytes
    /// is not long enough.
    #[error("buffer passed for identity check is too short")]
    IdentityLength,

    /// Error generated when a vault algorithm identifier byte is wrong.
    #[error("unknown algorithm {0}")]
    UnknownAlgorithm(u8),

    /// Error generated when an AGE version is not supported.
    #[error("unknown AGE version {0}")]
    UnknownAgeVersion(u8),

    /// Error generated when a vault algorithm string identifier is wrong.
    #[error("invalid algorithm {0}")]
    InvalidAlgorithm(String),

    /// Error generated when a nonce size is unknown.
    #[error("unknown nonce size {0}")]
    UnknownNonceSize(u8),

    /// Error generated when the kind of a secret is unknown.
    #[error("unknown secret kind {0}")]
    UnknownSecretKind(u8),

    /// Error generated when the kind of a user field is unknown.
    #[error("unknown user field kind {0}")]
    UnknownUserFieldKind(u8),

    /// Error generated when the kind of a signer is unknown.
    #[error("unknown signer kind {0}")]
    UnknownSignerKind(u8),

    /// Error generated when the kind identifier of an event is unknown.
    #[error("unknown event kind {0}")]
    UnknownEventKind(u16),

    /// Error generated when the kind of an identification secret is unknown.
    #[error("unknown identity kind {0}")]
    UnknownIdentityKind(u8),

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

    /// Error generated when attempting to verify a passphrase fails.
    ///
    /// This can happen when calling `verify()` on a `Vault` or `unlock()`
    /// on a `Gatekeeper`.
    #[error("passphrase verification failed")]
    PassphraseVerification,

    /// Error generated when a login vault does not contain
    /// the identity bit flag.
    #[error("vault is not an identity vault")]
    NotIdentityVault,

    /// Error generated when a login vault does not contain a signing key.
    #[error("identity vault does not contain a signing key")]
    NoIdentitySigner,

    /// Error generated when a login signing secret is of the wrong kind.
    #[error("identity vault signing secret is of the wrong kind")]
    IdentitySignerKind,

    /// Error generated when a login vault is missing a secret.
    #[error("identity vault does not contain a secret")]
    NoIdentitySecret,

    /// Error generated when a vault has not been initialized (no encrypted meta data).
    #[error("vault is not initialized")]
    VaultNotInit,

    /// Error generated attempting to a initialize a vault when it has already been initialized.
    #[error("vault is already initialized")]
    VaultAlreadyInit,

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

    /// Error generated when WAL row data does not match the commit hash.
    #[error("row checksums do not match, expected {commit} but got {value}")]
    HashMismatch {
        /// Expected commit hash.
        commit: String,
        /// Commit hash of the value.
        value: String,
    },

    /// Error generated when a a WAL file does not begin with a create vault event.
    #[error("first record in a WAL log must be a create vault event")]
    WalCreateEventMustBeFirst,

    /// Error generated when a WAL create vault event is not the first record.
    #[error("got a WAL log create vault event that is not the first record")]
    WalCreateEventOnlyFirst,

    /// Error generated when a commit tree is expected to have a root.
    #[error("commit tree does not have a root")]
    NoRootCommit,

    /// Error generated when a sync event cannot be converted to a WAL event.
    #[error("sync event cannot be converted to a WAL event")]
    SyncWalConvert,

    /// Error generated when an RPC method kind is invalid.
    #[error("method kind {0} is invalid")]
    InvalidMethod(u16),

    /// Error generated when a value is expected to be all digits.
    #[error("expected only digit characters")]
    NotDigit,

    /// Error generated when decoding vault flags has invalid bits.
    #[error("bits for vault flags are invalid")]
    InvalidVaultFlags,

    /// Error generated when decoding secret flags has invalid bits.
    #[error("bits for secret flags are invalid")]
    InvalidSecretFlags,

    /// Error generated when decoding a vault purpose identifier that
    /// is not known.
    #[error("purpose identifier {0} is unknown")]
    UnknownPurpose(u8),

    /// Error generated an archive does not contain a manifest file.
    #[error("archive does not contain a manifest file")]
    NoArchiveManifest,

    /// Error generated an archive does not contain a manifest file.
    #[error("archive does contain the vault {0}")]
    NoArchiveVault(PathBuf),

    /// Error generated an archive does not contain a manifest file.
    #[error("archive file {0} does not match the manifest checksum")]
    ArchiveChecksumMismatch(String),

    /// Error generated converting now to the zip date time format.
    #[error("zip date time is invalid")]
    ZipDateTime,

    /// Generic boxed error.
    #[error(transparent)]
    Boxed(#[from] Box<dyn std::error::Error + Send + Sync>),

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

    /// Error generated parsing URLs.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    /// Error generated parsing UUIDs.
    #[error(transparent)]
    Uuid(#[from] uuid::Error),

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /*
    /// Error generated from the binary serializer / deserializer.
    #[error(transparent)]
    Binary(#[from] serde_binary::Error),
    */
    /// Error generated from the binary reader / writer.
    #[error(transparent)]
    BinaryStream(#[from] binary_stream::BinaryError),

    /// Error generated during AES encryption and decryption.
    #[error(transparent)]
    Aes(#[from] aes_gcm::Error),

    /*
    /// Error generated by the ECDSA library.
    #[error(transparent)]
    Ecdsa(#[from] k256::ecdsa::Error),
    */
    /// Error generated by elliptic curve library.
    #[error(transparent)]
    Elliptic(#[from] k256::elliptic_curve::Error),

    /// Error generated by the merkle tree library.
    #[error(transparent)]
    Merkle(#[from] rs_merkle::Error),

    /// Error generated converting time types.
    //#[cfg(not(target_arch = "wasm32"))]
    #[error(transparent)]
    Time(#[from] time::error::ComponentRange),

    /// Error generated formatting time.
    //#[cfg(not(target_arch = "wasm32"))]
    #[error(transparent)]
    TimeFormat(#[from] time::error::Format),

    /// Error generated parsing time.
    //#[cfg(not(target_arch = "wasm32"))]
    #[error(transparent)]
    TimeParse(#[from] time::error::Parse),

    /// Error generated creating format descriptions for date formatting.
    //#[cfg(not(target_arch = "wasm32"))]
    #[error(transparent)]
    InvalidFormat(#[from] time::error::InvalidFormatDescription),

    /// Error generated parsing PEM files.
    #[error(transparent)]
    Pem(#[from] pem::PemError),

    /// Error generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Error generated by the address library.
    #[error(transparent)]
    Address(#[from] web3_address::Error),

    /// Error generated by the crypto library.
    #[error(transparent)]
    ChaCha(#[from] chacha20poly1305::Error),

    /// Error generated by the URN library.
    #[error(transparent)]
    Urn(#[from] urn::Error),

    /// Error generated by the signature library.
    #[error(transparent)]
    Signature(#[from] web3_signature::SignatureError),

    /// Error generated by the password entropy library.
    #[error(transparent)]
    Zxcvbn(#[from] zxcvbn::ZxcvbnError),

    /// Error generated by the zip library.
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),

    /// Error generated when converting integers.
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),

    /// Error generated by the Ed25519 library.
    #[error(transparent)]
    Ed25519(#[from] ed25519_dalek::ed25519::Error),

    /// Error generated by the Base58 library.
    #[error(transparent)]
    Base58(#[from] bs58::encode::Error),
}
