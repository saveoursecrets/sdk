//! Types encoded in query strings.
use serde::{Deserialize, Serialize};
use sos_core::{ExternalFileName, SecretId, VaultId};

/// Query string for moving a file.
#[derive(Debug, Serialize, Deserialize)]
pub struct MoveFileQuery {
    /// Folder identifier.
    pub vault_id: VaultId,
    /// Secret identifier.
    pub secret_id: SecretId,
    /// External file name.
    pub name: ExternalFileName,
}
