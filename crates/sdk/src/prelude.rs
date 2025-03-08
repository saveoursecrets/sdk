//! Prelude re-exports common types.
pub use sos_core::{
    constants::*, crypto::*, decode, device::*, encode, events::*,
    AccountRef, ErrorExt, FolderRef, Paths, PublicIdentity, SecretId,
    SecretPath, UtcDateTime, VaultCommit, VaultEntry, VaultFlags, VaultId,
};
pub use sos_login::{device::*, Identity, IdentityFolder};
pub use sos_password::diceware::generate_passphrase;
pub use sos_vault::{
    secret::{
        FileContent, IdentityKind, Secret, SecretFlags, SecretMeta,
        SecretRef, SecretRow, SecretSigner, SecretType, UserData,
    },
    AccessPoint, BuilderCredentials, ChangePassword, Contents,
    EncryptedEntry, Header, Summary, Vault, VaultBuilder,
};
