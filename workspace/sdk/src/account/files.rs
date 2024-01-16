//! File manager to keep external files in sync
//! as secrets are created, updated and moved.

use crate::{
    account::{Account, LocalAccount, SecretChange},
    storage::AccessOptions,
    vault::{
        secret::{Secret, SecretId, SecretMeta},
        Summary,
    },
    Error, Result,
};
use std::path::Path;

impl LocalAccount {
    /// Update a file secret.
    ///
    /// If the secret exists and is not a file secret it will be
    /// converted to a file secret so take care to ensure you only
    /// use this on file secrets.
    pub async fn update_file(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        path: impl AsRef<Path>,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<SecretChange<Error>> {
        let path = path.as_ref().to_path_buf();
        let secret: Secret = path.try_into()?;
        self.update_secret(
            secret_id,
            meta,
            Some(secret),
            options,
            destination,
        )
        .await
    }
}
