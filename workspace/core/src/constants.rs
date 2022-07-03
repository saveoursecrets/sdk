//! Constants shared between the client and server.

/// Constants for file extensions.
pub mod extensions {
    /// File extension used when deleting WAL files.
    pub const WAL_DELETED_EXT: &str = "wal.deleted";

    /// File extension used when creating a WAL file backup.
    pub const WAL_BACKUP_EXT: &str = "wal.backup";
}

/// Constants for header names.
pub mod headers {
    /// Constant for the signed message header.
    pub const X_SIGNED_MESSAGE: &str = "x-signed-message";

    /// Constant for the commit proof header.
    pub const X_COMMIT_PROOF: &str = "x-commit-proof";

    /// Constant for the match proof header.
    pub const X_MATCH_PROOF: &str = "x-match-proof";
}
