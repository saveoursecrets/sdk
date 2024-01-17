//! Adds migration functions to an account.
use crate::{
    account::{Account, FolderCreate, LocalAccount},
    crypto::AccessKey,
    encode,
    events::EventKind,
    identity::Identity,
    migrate::Convert,
    vault::{VaultBuilder, VaultId},
    Error, Result,
};
use std::path::{Path, PathBuf};

#[cfg(feature = "audit")]
use crate::audit::AuditEvent;

impl LocalAccount {
    /// Generic CSV import implementation.
    pub(super) async fn import_csv<P: AsRef<Path>>(
        &mut self,
        path: P,
        folder_name: String,
        converter: impl Convert<Input = PathBuf>,
    ) -> Result<FolderCreate<Error>> {
        let paths = self.paths();

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                EventKind::ImportUnsafe,
                self.address().clone(),
                None,
            );
            paths.append_audit_events(vec![audit_event]).await?;
        }

        let vaults = Identity::list_local_folders(&paths).await?;
        let existing_name =
            vaults.iter().find(|(s, _)| s.name() == folder_name);

        let vault_passphrase = self.user()?.generate_folder_password()?;

        let vault_id = VaultId::new_v4();
        let name = if existing_name.is_some() {
            format!("{} ({})", folder_name, vault_id)
        } else {
            folder_name
        };

        let vault = VaultBuilder::new()
            .id(vault_id)
            .public_name(name)
            .password(vault_passphrase.clone(), None)
            .await?;

        // Parse the CSV records into the vault
        let key = vault_passphrase.clone().into();
        let vault = converter
            .convert(path.as_ref().to_path_buf(), vault, &key)
            .await?;

        let buffer = encode(&vault).await?;
        let key: AccessKey = vault_passphrase.clone().into();
        let result = self.import_folder_buffer(&buffer, key, false).await?;

        self.user_mut()?
            .save_folder_password(vault.id(), vault_passphrase.clone().into())
            .await?;

        Ok(result)
    }
}
