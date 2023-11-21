//! Constants for file formats, folder names etc.

/// Application name.
pub const APP_NAME: &str = "SaveOurSecrets";

/// Application author.
pub const APP_AUTHOR: &str = "SaveOurSecrets";

/*
/// Bundle identifier for MacOS and iOS.
///
/// This is used to determine the default local storage directory
/// for the macos and ios platforms.
pub const BUNDLE_ID: &str = "com.saveoursecrets";
*/

/// File name for audit logs.
pub const AUDIT_FILE_NAME: &str = "audit.dat";

/// Constants for file identity.
mod identity {
    /// Audit log identity magic bytes (SOSA).
    pub const AUDIT_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x41];

    /// Write-ahead log identity magic bytes (SOSW).
    pub const EVENT_LOG_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x57];

    /// Patch file identity magic bytes (SOSP).
    pub const PATCH_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x50];

    /// Vault file identity magic bytes (SOSV).
    pub const VAULT_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x56];

    /// Remote procedure call identity magic bytes (SOSR).
    pub const RPC_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x52];
}

/// Constants for file extensions.
mod extensions {
    /// File extension used for event log files.
    pub const EVENT_LOG_EXT: &str = "events";

    /// File extension used when deleting event log files.
    pub const EVENT_LOG_DELETED_EXT: &str = "events.deleted";

    /// File extension used for vault files.
    pub const VAULT_EXT: &str = "vault";

    /// File extension used when creating a vault file backup.
    pub const VAULT_BACKUP_EXT: &str = "vault.backup";
}

/// Constants for vaults.
mod vault {
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

    /// Mime type for event logs.
    pub const MIME_TYPE_EVENT: &str = "application/sos+event";

    /// Mime type for patches.
    pub const MIME_TYPE_PATCH: &str = "application/sos+patch";

    /// Mime type for RPC packets.
    pub const MIME_TYPE_RPC: &str = "application/sos+rpc";
}

mod rpc {
    /// Noise protocol handshake initiation.
    pub const HANDSHAKE_INITIATE: &str = "Handshake.initiate";

    /// Account status method call.
    pub const ACCOUNT_STATUS: &str = "Account.status";

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

    /// Event log load method call.
    pub const EVENT_LOG_LOAD: &str = "Events.load";

    /// Event log status method call.
    pub const EVENT_LOG_STATUS: &str = "Events.status";

    /// Event log diff method call.
    pub const EVENT_LOG_DIFF: &str = "Events.diff";

    /// Event log patch method call.
    pub const EVENT_LOG_PATCH: &str = "Events.patch";

    /// Event log save method call.
    pub const EVENT_LOG_SAVE: &str = "Events.save";
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

    /// Directory to store log files.
    pub const LOGS_DIR: &str = "logs";
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
pub use identity::*;
pub use mime::*;
pub use rpc::*;
pub use scheme::*;
pub use vault::*;
