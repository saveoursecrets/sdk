//! Prelude re-exports common types.
pub use sos_core::{
    AccountRef, ErrorExt, FolderRef, Paths, PublicIdentity, SecretId,
    SecretPath, UtcDateTime, VaultCommit, VaultEntry, VaultFlags, VaultId,
    constants::*, crypto::*, decode, device::*, encode, events::*,
};
pub use sos_login::{Identity, IdentityFolder, device::*};
pub use sos_password::diceware::generate_passphrase;
pub use sos_vault::{
    AccessPoint, BuilderCredentials, ChangePassword, Contents,
    EncryptedEntry, Header, Summary, Vault, VaultBuilder,
    secret::{
        FileContent, IdentityKind, Secret, SecretFlags, SecretMeta,
        SecretRef, SecretRow, SecretSigner, SecretType, UserData,
    },
};
