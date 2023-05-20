//! Constants for file formats, folder names etc.

/// Bundle identifier for MacOS and iOS.
///
/// This is used to determine the default local storage directory
/// for the macos and ios platforms.
pub const BUNDLE_ID: &str = "com.saveoursecrets";

/// Constants for file identity.
mod identity {
    /// Audit log identity magic bytes (SOSA).
    pub const AUDIT_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x41];

    /// Write-ahead log identity magic bytes (SOSW).
    pub const WAL_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x57];

    /// Patch file identity magic bytes (SOSP).
    pub const PATCH_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x50];

    /// Vault file identity magic bytes (SOSV).
    pub const VAULT_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x56];

    /// Agent file identity magic bytes (SOSG).
    pub const AGENT_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x47];

    /// Remote procedure call identity magic bytes (SOSR).
    pub const RPC_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x52];
}

/// Constants for file extensions.
mod extensions {
    /// File extension used for WAL files.
    pub const WAL_EXT: &str = "wal";

    /// File extension used when deleting WAL files.
    pub const WAL_DELETED_EXT: &str = "wal.deleted";

    /// File extension used for vault files.
    pub const VAULT_EXT: &str = "vault";

    /// File extension used when creating a vault file backup.
    pub const VAULT_BACKUP_EXT: &str = "vault.backup";

    /// File extension used for patch files.
    pub const PATCH_EXT: &str = "patch";
}

/// Constants for header names.
mod headers {
    /// Constant for the session identifier header.
    pub const X_SESSION: &str = "x-session";
}

/// Constants for vaults.
mod vault {
    /// Vault version identifier.
    pub const VAULT_VERSION: u16 = 0;

    /// Default public name for a vault.
    pub const DEFAULT_VAULT_NAME: &str = "Documents";

    /// Default name for the archive vault.
    pub const DEFAULT_ARCHIVE_VAULT_NAME: &str = "Archive";

    /// Default name for the contacts vault.
    pub const DEFAULT_CONTACTS_VAULT_NAME: &str = "Contacts";

    /// Default name for the authenticator vault.
    pub const DEFAULT_AUTHENTICATOR_VAULT_NAME: &str = "Authenticator";

    /// Login vault signing key name.
    pub const LOGIN_SIGNING_KEY_URN: &str = "urn:sos:identity:signer";

    /// Login vault AGE key name.
    ///
    /// This key is used to encrypt files for specific recipients.
    pub const LOGIN_AGE_KEY_URN: &str = "urn:sos:identity:age";

    /// Login vault file encryption password.
    ///
    /// This password is used to encrypt external files that are not
    /// embedded in a vault.
    pub const FILE_PASSWORD_URN: &str = "urn:sos:identity:file";

    /// Device key used to identify a device.
    pub const DEVICE_KEY_URN: &str = "urn:sos:device:key";
}

/// Constants for MIME types.
mod mime {
    /// Mime type for vaults.
    pub const MIME_TYPE_VAULT: &str = "application/sos+vault";
}

mod rpc {
    /// Session offer method call.
    pub const SESSION_OFFER: &str = "Session.offer";

    /// Session verify method call.
    pub const SESSION_VERIFY: &str = "Session.verify";

    /// Account create method call.
    pub const ACCOUNT_CREATE: &str = "Account.create";

    /// Account list vaults method call.
    pub const ACCOUNT_LIST_VAULTS: &str = "Account.list_vaults";

    /// Vault create method call.
    pub const VAULT_CREATE: &str = "Vault.create";

    /// Vault save method call.
    pub const VAULT_SAVE: &str = "Vault.save";

    /// Vault delete method call.
    pub const VAULT_DELETE: &str = "Vault.delete";

    /// WAL load method call.
    pub const WAL_LOAD: &str = "Wal.load";

    /// WAL status method call.
    pub const WAL_STATUS: &str = "Wal.status";

    /// WAL patch method call.
    pub const WAL_PATCH: &str = "Wal.patch";

    /// WAL save method call.
    pub const WAL_SAVE: &str = "Wal.save";
}

/// Constants for directory names.
mod folders {
    /// Directory to store vaults.
    pub const VAULTS_DIR: &str = "vaults";

    /// Directory to store local provider data.
    pub const LOCAL_DIR: &str = "local";

    /// Directory to store identity vaults.
    pub const IDENTITY_DIR: &str = "identity";

    /// Directory to store files.
    pub const FILES_DIR: &str = "files";

    /// Directory to store trusted devices public keys.
    pub const DEVICES_DIR: &str = "devices";

    /// Directory to store temporary files.
    pub const TEMP_DIR: &str = "temp";

    /// Directory to store deleted files.
    pub const TRASH_DIR: &str = "trash";
}

mod archive {
    /// Manifest file for archives.
    pub const ARCHIVE_MANIFEST: &str = "sos-manifest.json";
}

mod scheme {
    /// Scheme for P2P URIs.
    pub const P2P_URI_SCHEME: &str = "sos+p2p";
}

pub use archive::*;
pub use extensions::*;
pub use folders::*;
pub use headers::*;
pub use identity::*;
pub use mime::*;
pub use rpc::*;
pub use scheme::*;
pub use vault::*;
