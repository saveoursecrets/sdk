//! Constants shared between the client and server.

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
}

/// Constants for file extensions.
mod extensions {
    /// File extension used when deleting WAL files.
    pub const WAL_DELETED_EXT: &str = "wal.deleted";

    /// File extension used when creating a WAL file backup.
    pub const WAL_BACKUP_EXT: &str = "wal.backup";

    /// File extension used when creating a vault file backup.
    pub const VAULT_BACKUP_EXT: &str = "vault.backup";
}

/// Constants for header names.
mod headers {
    /// Constant for the signed message header.
    pub const X_SIGNED_MESSAGE: &str = "x-signed-message";

    /// Constant for the commit proof header.
    pub const X_COMMIT_PROOF: &str = "x-commit-proof";

    /// Constant for the match proof header.
    pub const X_MATCH_PROOF: &str = "x-match-proof";
}

pub use extensions::*;
pub use headers::*;
pub use identity::*;
