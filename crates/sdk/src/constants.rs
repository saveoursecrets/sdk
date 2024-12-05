//! Constants for file formats, folder names etc.

/// Application name.
pub const APP_NAME: &str = "SaveOurSecrets";

/// Application author.
pub const APP_AUTHOR: &str = "SaveOurSecrets";

/// File name for audit logs.
pub const AUDIT_FILE_NAME: &str = "audit.dat";

/// Name for GUI IPC sockets.
pub const IPC_GUI_SOCKET_NAME: &str = "com.saveoursecrets.gui.sock";

/// Name for CLI IPC sockets.
pub const IPC_CLI_SOCKET_NAME: &str = "com.saveoursecrets.cli.sock";

/// Constants for file identity.
mod identity {
    /// Audit log identity magic bytes (SOSA).
    pub const AUDIT_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x41];

    /// Account event log identity magic bytes (SOSU).
    pub const ACCOUNT_EVENT_LOG_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x55];

    /// Folder event log identity magic bytes (SOSW).
    pub const FOLDER_EVENT_LOG_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x57];

    /// Device event log identity magic bytes (SOSD).
    pub const DEVICE_EVENT_LOG_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x44];

    /// File event log identity magic bytes (SOSF).
    pub const FILE_EVENT_LOG_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x46];

    /// Patch file identity magic bytes (SOSP).
    pub const PATCH_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x50];

    /// Vault file identity magic bytes (SOSV).
    pub const VAULT_IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x56];
}

/// Constants for file extensions.
mod extensions {
    /// File extension used for event log files.
    pub const EVENT_LOG_EXT: &str = "events";

    /// File extension used for vault files.
    pub const VAULT_EXT: &str = "vault";

    /// File extension for JSON documents.
    pub const JSON_EXT: &str = "json";
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
}

mod urn {
    /// URN namespace identifier.
    pub const URN_NID: &str = "sos";

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

    /// Namespace for vault passwords.
    ///
    /// The namespace is followed by the vault identifier.
    pub const VAULT_NSS: &str = "vault:";

    /// Device signing key.
    pub const DEVICE_KEY_URN: &str = "urn:sos:device:key";
}

/// Constants for directory names.
mod folders {
    /// Directory to store vaults.
    pub const VAULTS_DIR: &str = "vaults";

    /// Directory to store pending folders.
    ///
    /// Pending folders are folders with the LOCAL
    /// flag set that were created from an
    /// [AccountEvent::CreateFolder] event but won't have any
    /// events yet unless a NO_SYNC flag has been removed.
    pub const PENDING_DIR: &str = "pending";

    /// Directory to store data for clients.
    pub const LOCAL_DIR: &str = "local";

    /// Directory to store data for servers.
    pub const REMOTE_DIR: &str = "remote";

    /// Directory to store identity vaults.
    pub const IDENTITY_DIR: &str = "identity";

    /// Directory to store files.
    pub const FILES_DIR: &str = "files";

    /// Directory to store log files.
    pub const LOGS_DIR: &str = "logs";

    /// Name of the file for account events.
    pub const ACCOUNT_EVENTS: &str = "account";

    /// Name of the file for device events.
    pub const DEVICE_EVENTS: &str = "devices";

    /// Name of the file for file events.
    pub const FILE_EVENTS: &str = "files";

    /// Name of the file for remote origins.
    pub const REMOTES_FILE: &str = "servers";

    /// Name of the vault file that stores the device
    /// signing key.
    pub const DEVICE_FILE: &str = "device";

    /// Lock file for an account.
    pub const LOCK_FILE: &str = "account.lock";

    /// Lock file for an app.
    pub const APP_LOCK_FILE: &str = "app.lock";
}

/// File names.
mod files {
    /// Manifest file for archives.
    pub const ARCHIVE_MANIFEST: &str = "sos-manifest.json";
}

/// Environment variables.
mod env_vars {
    /// Sets the storage directory.
    pub const SOS_DATA_DIR: &str = "SOS_DATA_DIR";
    /// Disable networking.
    pub const SOS_OFFLINE: &str = "SOS_OFFLINE";
    /// Shell session prompt.
    pub const SOS_PROMPT: &str = "SOS_PROMPT";
}

pub use self::urn::*;
pub use env_vars::*;
pub use extensions::*;
pub use files::*;
pub use folders::*;
pub use identity::*;
pub use vault::*;
