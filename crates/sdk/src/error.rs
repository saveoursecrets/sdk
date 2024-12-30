//! Errors generated by the core library.
use std::path::PathBuf;
use thiserror::Error;
use urn::Urn;
use uuid::Uuid;

use crate::{
    commit::CommitHash,
    vault::{secret::SecretId, VaultId},
};

/// Error thrown by the core library.
#[derive(Debug, Error)]
pub enum Error {
    /// Generic error message used when converting from some libraries
    /// that return a `String` as an error.
    #[error("{0}")]
    Message(String),

    /// Permission denied.
    ///
    /// If a shared vault is set to private shared access and
    /// somebody other than the owner attempts to write to encrypt
    /// a shared entry this error is generated.
    #[error("permission denied")]
    PermissionDenied,

    /// Error generated when a path is not a file.
    #[error("path {0} is not a file")]
    NotFile(PathBuf),

    /// Error generated accessing an account that is not
    /// authenticated.
    #[error("account not authenticated, sign in required")]
    NotAuthenticated,

    /// Error generated when no storage is configured.
    #[error(
        "account is empty, you may need to initialize the account or sign in"
    )]
    NoStorage,

    /// Error generated if we could not determine a cache directory.
    #[error("could not determine cache directory")]
    NoCache,

    /// Error generated when a search index is required.
    #[error("no search index")]
    NoSearchIndex,

    /// Error generated when a file encryption password is required.
    #[error("no file password")]
    NoFilePassword,

    /// Error generated when an open folder is expected.
    #[error("no open folder")]
    NoOpenFolder,

    /// Error generated when a device signer is expected.
    #[error("no device available")]
    NoDevice,

    /// Error generated when no default folder is available.
    #[error("no default folder")]
    NoDefaultFolder,

    /// Error generated when a PEM-encoded certificate is invalid.
    #[error("invalid PEM encoding")]
    PemEncoding,

    /// Error generated when a file secret is expected.
    #[error("not a file secret")]
    NotFileContent,

    /// Error generated when attempting to unarchive a secret that
    /// is not archived.
    #[error("cannot unarchive, not archived")]
    NotArchived,

    /// Error generated when an archive folder is not available.
    #[error("archive folder does not exist")]
    NoArchive,

    /// Error generated when attempting to archive a secret that
    /// is already archived.
    #[error("cannot move to archive, already archived")]
    AlreadyArchived,

    /// Error generated when a contacts folder is not available.
    #[cfg(feature = "contacts")]
    #[error("no contacts folder")]
    NoContactsFolder,

    /// Error generated when a secret is not a contact secret.
    #[cfg(feature = "contacts")]
    #[error("not a contact")]
    NotContact,

    /// Error generated when a signing key is required.
    #[error("no signer")]
    NoSigner,

    /// Error generated when a recovery group threshold is too small.
    #[error("recovery group threshold '{0}' is too small, must be >= 2")]
    RecoveryThreshold(u8),

    /// Error generated attempting to encrypt or decrypt with the
    /// wrong cipher.
    #[error(r#"bad cipher, expecting "{0}" but got "{1}""#)]
    BadCipher(String, String),

    /// Error generated when a directory is expected.
    #[error("path {0} is not a directory")]
    NotDirectory(PathBuf),

    /// Error generated when attempting to parse a key/value pair.
    #[error(r#"invalid key value "{0}""#)]
    InvalidKeyValue(String),

    /// Error generated when a vault identity byte is wrong.
    #[error("bad identity byte {0:#04x} at position {1} expecting {2}")]
    BadIdentity(u8, usize, String),

    /// Error generated when a buffer used to read identity bytes
    /// is not long enough.
    #[error("buffer passed for identity check is too short")]
    IdentityLength,

    /// Error generated when vault identifiers must match.
    #[error("identifier '{0}' does not match '{1}'")]
    VaultIdentifierMismatch(VaultId, VaultId),

    /// Error generated when a vault cipher identifier byte is wrong.
    #[error("unknown cipher {0}")]
    UnknownCipher(u8),

    /// Error generated when a vault cipher string identifier is wrong.
    #[error("invalid cipher {0}")]
    InvalidCipher(String),

    /// Error generated when a vault key derivation function string
    /// identifier is wrong.
    #[error("invalid key derivation function {0}")]
    InvalidKeyDerivation(String),

    /// Error generated when the kind of a secret is unknown.
    #[error("unknown secret kind {0}")]
    UnknownSecretKind(u8),

    /// Error generated when the kind identifier of an event is unknown.
    #[error("unknown event kind {0}")]
    UnknownEventKind(u16),

    /// Error generated when the kind of an identification secret is unknown.
    #[error("unknown identity kind {0}")]
    UnknownIdentityKind(u8),

    /// Error generated when the kind of a shared access variant is unknown.
    #[error("unknown shared access kind {0}")]
    UnknownSharedAccessKind(u8),

    /// Error generated when the namespace identifier for a URN is wrong.
    #[error(
        "invalid URN namespace identifier, expected '{0}' but got '{1}'"
    )]
    InvalidUrnNid(String, String),

    /// Error generated when a URN expects an account address.
    #[error("account address expected in URN '{0}'")]
    NoUrnAddress(String),

    /// Error generated when a URN expects a folder identifier.
    #[error("folder identifier expected in URN '{0}'")]
    NoUrnFolderId(String),

    /// Error generated when a URN expects a secret identifier.
    #[error("secret identifier expected in URN '{0}'")]
    NoUrnSecretId(String),

    /// Error generated when an AeadPack contains a nonce that
    /// is invalid for the decryption cipher.
    #[error("invalid nonce")]
    InvalidNonce,

    #[deprecated]
    /// Error generated attempting to convert to a change event.
    #[error("not compatible with change event")]
    NoChangeEvent,

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

    /// Error generated when attempting to verify a password fails.
    ///
    /// This can happen when calling `verify()` on a `Vault` or `unlock()`
    /// on a `Gatekeeper`.
    #[error("password verification failed")]
    PassphraseVerification,

    /// Error generated when a login vault does not contain
    /// the identity bit flag.
    #[error("vault is not an identity vault")]
    NotIdentityFolder,

    /// Error generated when a vault does not contain a secret by URN.
    #[error("vault {0} does not contain {1}")]
    NoSecretUrn(VaultId, Urn),

    /// Error generated when a vault does not contain a secret by identifier.
    #[error("vault {0} does not contain {1}")]
    NoSecretId(VaultId, SecretId),

    /// Error generated when a signing key could not be
    /// found in an identity vault.
    #[error("identity vault does not contain a valid account signing key")]
    NoSigningKey,

    /// Error generated when an identity key could not be
    /// found in an identity vault.
    #[error("identity vault does not contain a valid account identity key")]
    NoIdentityKey,

    /// Error generated when a vault has not been initialized (no encrypted meta data).
    #[error("vault is not initialized")]
    VaultNotInit,

    /// Error generated attempting to a initialize a vault when it has already been initialized.
    #[error("vault is already initialized")]
    VaultAlreadyInit,

    /// Error generated when the type identifier for a public key is unknown.
    #[error("unknown key type identifier")]
    UnknownKeyTypeId,

    /// Error generated when a public key has the wrong length.
    #[error(
        "public key is wrong length, expecting {0} bytes but got {1} bytes"
    )]
    InvalidPublicKeyLength(u8, usize),

    /// Error generated when event log row data does not match the commit hash.
    #[error("row '{id}' checksums do not match, expected {commit} but got {value}")]
    VaultHashMismatch {
        /// Expected commit hash.
        commit: String,
        /// Commit hash of the value.
        value: String,
        /// Record identifier.
        id: Uuid,
    },

    /// Error generated when event log row data does not match the commit hash.
    #[error("row checksums do not match, expected {commit} but got {value}")]
    HashMismatch {
        /// Expected commit hash.
        commit: String,
        /// Commit hash of the value.
        value: String,
    },

    /// Error generated when a a event log file does not begin with a create vault event.
    #[error("first record in an event log must be a create vault event")]
    CreateEventMustBeFirst,

    /// Error generated when a event log create vault event is not the first record.
    #[error(
        "got an event log create vault event that is not the first record"
    )]
    CreateEventOnlyFirst,

    /// Error generated when a commit tree is expected to have a root.
    #[error("commit tree does not have a root")]
    NoRootCommit,

    /// Error generated when a commit tree is expected to have a last commit.
    #[error("commit tree does not have a last commit")]
    NoLastCommit,

    /// Error generated when a target commit hash could not be found.
    #[error("commit '{0}' could not be found")]
    CommitNotFound(CommitHash),

    /// Error generated trying to rewind an event log.
    #[error("rewind failed as pruned commits is greater than the length of the in-memory tree")]
    RewindLeavesLength,

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

    /// Error generated parsing an AGE identity from a string.
    #[error("failed to parse AGE identity: {0}")]
    AgeIdentityParse(String),

    /// Error generated when a folder password in the identity
    /// vault could not be located.
    #[error("could not find folder password for '{0}'")]
    NoFolderPassword(VaultId),

    /// Error generated when a file encryption password could not be found.
    #[error("could not find file encryption password in identity folder")]
    NoFileEncryptionPassword,

    /// Error generated when a vault entry in an identity vault is of
    /// the wrong secret kind.
    #[error("vault entry for {0} is of an unexpected type")]
    VaultEntryKind(String),

    /// Error generated when an archive is for an address that does
    /// not exist locally when we are expecting an archive to be imported
    /// in the context of an existing account.
    #[error("could not find account for archive address {0}")]
    NoArchiveAccount(String),

    /// Error generated attempting to restore an account from an archive
    /// whilst not authenticated and the address for the archive matches
    /// an account that already exists.
    #[error("account for archive address {0} already exists")]
    ArchiveAccountAlreadyExists(String),

    /// Error generated when the default vault for an account could not be found.
    #[error("could not find the default vault for {0}")]
    NoDefaultVault(String),

    /// Error generated when a vault file could not be located.
    #[error("could not find vault file for {0}")]
    NoVaultFile(String),

    /// Error generated when an account does not exist.
    #[error("could not find account {0}")]
    NoAccount(String),

    /// Error generated when an archive signing key address
    /// does not match the address in the archive manifest.
    #[error("archive manifest address does not match identity signing key address")]
    ArchiveAddressMismatch,

    /// Error generated when an archive does not contain a default vault.
    #[error("archive does not contain a default vault")]
    NoArchiveDefaultVault,

    /// Error generated when a session does not exist.
    #[error("session does not exist")]
    NoSession,

    /// Error generated when a session identity signature does not
    /// match the initial address.
    #[error("bad session identity signature")]
    BadSessionIdentity,

    /// Error generated when attempting to compute a shared secret
    /// before a session identity has been proven.
    #[error("session identity has not been proven")]
    NoSessionIdentity,

    /// Error generated when a session does not yet have a salt.
    #[error("session salt has not been set")]
    NoSessionSalt,

    /// Error generated when a session shared secret has not yet been
    /// created.
    #[error("session shared secret has not been set")]
    NoSessionSharedSecret,

    /// Error generated when a session key does not exist.
    #[error("session key does not exist")]
    NoSessionKey,

    /// Error generated when a session receives a nonce that is equal to
    /// or less than the current server session nonce.
    #[error("bad nonce, possible replay attack")]
    BadNonce,

    /// Error generated when an ECDSA signing key is expected.
    #[error("not ECDSA signing key")]
    NotEcdsaKey,

    /// Error generated when an Ed25519 signing key is expected.
    #[error("not Ed25519 signing key")]
    NotEd25519Key,

    /// Error generated when attempting to use an asymmetric
    /// private key with a symmetric cipher.
    #[error("symmetric private key required for symmetric cipher")]
    NotSymmetric,

    /// Error generated when attempting to use a symmetric
    /// private key with an asymmetric cipher.
    #[error("asymmetric private key required for asymmetric cipher")]
    NotAsymmetric,

    /// Error generated when attempting to parse an AGE identity.
    #[error(r#"invalid x25519 identity "{0}""#)]
    InvalidX25519Identity(String),

    /// Error generated when an attachment could not be found.
    #[error(r#"attachment "{0}" not found"#)]
    FieldNotFound(SecretId),

    /// Error generated attempting to access a vault that is not available.
    #[error("cache not available for {0}")]
    CacheNotAvailable(Uuid),

    /// Error generated when unlocking a vault failed.
    #[error("failed to unlock vault")]
    VaultUnlockFail,

    /// Error generated attempting to make changes to the current
    /// vault but no vault is open.
    #[error("no vault is available, vault must be open")]
    NoOpenVault,

    /// Error generated when a secret could not be found.
    #[error(r#"secret "{0}" not found"#)]
    SecretNotFound(SecretId),

    /// Error generated when an external file could not be parsed.
    #[error("external file reference '{0}' could not be parsed")]
    InvalidExternalFile(String),

    /// Error generated when an address has the wrong prefix.
    #[error("address must begin with 0x")]
    BadAddressPrefix,

    /// Invalid length, secp256k1 signatures are 65 bytes
    #[error("invalid signature length, got {0}, expected 65")]
    InvalidLength(usize),

    /// Expected a recovery identifier.
    #[error("recovery identifier is expected")]
    RecoveryId,

    /// Error generated when replacing events in an event log
    /// does not compute the same root hash as the expected
    /// checkpoint.
    #[error("checkpoint verification failed, expected root hash '{checkpoint}' but computed '{computed}', snapshot rollback completed: '{rollback_completed}' (snapshot: '{snapshot:?}')")]
    CheckpointVerification {
        /// Checkpoint root hash.
        checkpoint: CommitHash,
        /// Computed root hash.
        computed: CommitHash,
        /// Snapshot path.
        snapshot: Option<PathBuf>,
        /// Whether a rollback completed.
        rollback_completed: bool,
    },

    /// Attempt to apply a patch whose timestamp of the first event
    /// is younger than the last event in the log file.
    ///
    /// Typically, this can happen when clocks are out of sync.
    #[error("attempt to add an event in the past, this can happen if your clocks are out of sync, to fix this ensure that your device clock is using the correct date and time")]
    EventTimeBehind,

    #[cfg(feature = "clipboard")]
    /// Error when no clipboard is configured.
    #[error("clipboard is not configured")]
    NoClipboard,

    /// Error generated by the JSON path library when no nodes matched.
    #[cfg(feature = "clipboard")]
    #[error("paths '{0:?}' did not match any nodes")]
    JsonPathQueryEmpty(Vec<String>),

    /// Error generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Generic boxed error.
    #[error(transparent)]
    Boxed(#[from] Box<dyn std::error::Error + Send + Sync>),

    /// Error generated by password hash.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated converting from hexadecimal.
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

    /// Error generated during AES encryption and decryption.
    //#[error(transparent)]
    //Aes(#[from] aes_gcm::Error),

    /// Error generated by elliptic curve library.
    #[error(transparent)]
    Elliptic(#[from] k256::elliptic_curve::Error),

    /// Error generated by the merkle tree library.
    #[error(transparent)]
    Merkle(#[from] rs_merkle::Error),

    /// Error generated attempting to detect the system time zone.
    #[error(transparent)]
    TimeZone(#[from] time_tz::system::Error),

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

    /// Error generated parsing PEM files.
    #[error(transparent)]
    Pem(#[from] pem::PemError),

    /// Error generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Error generated by the crypto library.
    #[error(transparent)]
    ChaCha(#[from] chacha20poly1305::Error),

    /// Error generated by the URN library.
    #[error(transparent)]
    Urn(#[from] urn::Error),

    #[cfg(any(feature = "archive", feature = "migrate"))]
    /// Error generated by the async zip library.
    #[error(transparent)]
    Zip(#[from] async_zip::error::ZipError),

    /// Error generated when converting integers.
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),

    /// Error generated by the Ed25519 library.
    #[error(transparent)]
    Ed25519(#[from] ed25519_dalek::ed25519::Error),

    /// Error generated by the Base58 library.
    #[error(transparent)]
    Base58(#[from] bs58::encode::Error),

    /// Error generated by the SHA2 library.
    #[error(transparent)]
    Sha2DigestLength(#[from] sha2::digest::InvalidLength),

    /// Error generated by the AGE library when encrypting.
    #[error(transparent)]
    AgeEncrypt(#[from] age::EncryptError),

    /// Error generated by the AGE library when decrypting.
    #[error(transparent)]
    AgeDecrypt(#[from] age::DecryptError),

    /// Error generated when walking a directory.
    #[error(transparent)]
    Walk(#[from] walkdir::Error),

    /// Error generated when stripping a prefix from a path.
    #[error(transparent)]
    StripPrefix(#[from] std::path::StripPrefixError),

    /// Error generated when attempting to join a task.
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),

    /// Error generated by verifiable secret sharing library.
    #[error("vss error: {0}")]
    Vsss(String),

    /// Error generated converting from UTF8.
    #[error(transparent)]
    Utf8String(#[from] std::str::Utf8Error),

    /// Error generated by the vcard library.
    #[cfg(feature = "contacts")]
    #[error(transparent)]
    Vcard(#[from] crate::vcard4::Error),

    #[cfg(feature = "migrate")]
    /// Error generated by the migrate library.
    #[error(transparent)]
    Migrate(#[from] crate::migrate::Error),

    #[cfg(all(
        target_os = "macos",
        feature = "migrate",
        feature = "keychain-access"
    ))]
    /// Error generated by the keychain import library.
    #[error(transparent)]
    Keychain(#[from] crate::migrate::import::keychain::Error),

    #[cfg(all(
        target_os = "macos",
        feature = "migrate",
        feature = "keychain-access"
    ))]
    /// Error generated by the keychain parser library.
    #[error(transparent)]
    KeychainParser(#[from] keychain_parser::Error),

    /// Error generated by the signin notifications channel.
    #[error(transparent)]
    MpscLockedNotify(#[from] tokio::sync::mpsc::error::SendError<()>),

    /// Error generated by the TOTP library.
    #[error(transparent)]
    TotpUrl(#[from] totp_rs::TotpUrlError),

    /// Error generated by the clipboard library.
    #[cfg(feature = "clipboard")]
    #[error(transparent)]
    Clipboard(#[from] xclipboard::Error),
}

/// Extension functions for error types.
pub trait ErrorExt {
    /// Whether this is a secret not found error.
    fn is_secret_not_found(&self) -> bool;

    /// Whether this is a permission denied error.
    fn is_permission_denied(&self) -> bool;
}

impl ErrorExt for Error {
    fn is_secret_not_found(&self) -> bool {
        matches!(self, Error::SecretNotFound(_))
    }

    fn is_permission_denied(&self) -> bool {
        matches!(self, Error::PassphraseVerification)
    }
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Self::Message(value)
    }
}
