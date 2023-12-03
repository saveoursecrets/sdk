use crate::{events::Event, prelude::*, vfs, Result};
use std::{
    collections::HashMap,
    io::Cursor,
    path::{Path, PathBuf},
};

use crate::migrate::{
    export::PublicExport,
    import::{
        csv::{
            bitwarden::BitwardenCsv, chrome::ChromePasswordCsv,
            dashlane::DashlaneCsvZip, firefox::FirefoxPasswordCsv,
            macos::MacPasswordCsv, one_password::OnePasswordCsv,
        },
        ImportFormat, ImportTarget,
    },
    Convert,
};

/// Type alias for exporting from a local account.
pub type LocalExport<'a> = AccountExport<'a, ()>;

/// Type alias for importing into a local account.
pub type LocalImport<'a> = AccountImport<'a, ()>;

/// Adds migration support to an account.
pub struct AccountExport<'a, D> {
    account: &'a Account<D>,
}

impl<'a, D> AccountExport<'a, D> {
    /// Create a new account export.
    pub fn new(account: &'a Account<D>) -> Self {
        Self { account }
    }

    /// Write a zip archive containing all the secrets
    /// for the account unencrypted.
    ///
    /// Used to migrate an account to another provider.
    pub async fn export_unsafe_archive<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> crate::Result<()> {
        let paths = self.account.paths();

        let mut archive = Vec::new();
        let mut migration = PublicExport::new(Cursor::new(&mut archive));
        let vaults = LocalAccount::list_local_folders(&paths, false).await?;

        for (summary, _) in vaults {
            let (vault, _) =
                LocalAccount::load_local_vault(paths, summary.id(), false)
                    .await
                    .map_err(Box::from)?;
            let vault_passphrase = self
                .account
                .user()?
                .find_folder_password(summary.id())
                .await?;

            let mut keeper = Gatekeeper::new(vault);
            keeper.unlock(&vault_passphrase).await?;

            // Add the secrets for the vault to the migration
            migration.add(&keeper).await?;

            keeper.lock();
        }

        let mut files = HashMap::new();
        let buffer =
            serde_json::to_vec_pretty(self.account.user()?.account()?)?;
        // FIXME: constant for file name
        files.insert("account.json", buffer.as_slice());
        migration.append_files(files).await?;
        migration.finish().await?;

        vfs::write(path.as_ref(), &archive).await?;

        let audit_event = AuditEvent::new(
            EventKind::ExportUnsafe,
            self.account.address().clone(),
            None,
        );
        self.account.append_audit_logs(vec![audit_event]).await?;

        Ok(())
    }
}

/// Adds migration support to an account.
pub struct AccountImport<'a, D> {
    account: &'a mut Account<D>,
}

impl<'a, D> AccountImport<'a, D> {
    /// Create a new account import.
    pub fn new(account: &'a mut Account<D>) -> Self {
        Self { account }
    }

    /// Import secrets from another app.
    pub async fn import_file(
        &mut self,
        target: ImportTarget,
    ) -> Result<(Event, Summary)> {
        let (event, summary) = match target.format {
            ImportFormat::OnePasswordCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    OnePasswordCsv,
                )
                .await?
            }
            ImportFormat::DashlaneZip => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    DashlaneCsvZip,
                )
                .await?
            }
            ImportFormat::BitwardenCsv => {
                self.import_csv(target.path, target.folder_name, BitwardenCsv)
                    .await?
            }
            ImportFormat::ChromeCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    ChromePasswordCsv,
                )
                .await?
            }
            ImportFormat::FirefoxCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    FirefoxPasswordCsv,
                )
                .await?
            }
            ImportFormat::MacosCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    MacPasswordCsv,
                )
                .await?
            }
        };

        let audit_event = AuditEvent::new(
            EventKind::ImportUnsafe,
            self.account.address().clone(),
            None,
        );
        let create_event: AuditEvent =
            (self.account.address(), &event).into();

        self.account
            .append_audit_logs(vec![audit_event, create_event])
            .await?;

        Ok((event, summary))
    }

    /// Generic CSV import implementation.
    async fn import_csv<P: AsRef<Path>>(
        &mut self,
        path: P,
        folder_name: String,
        converter: impl Convert<Input = PathBuf>,
    ) -> Result<(Event, Summary)> {
        let paths = self.account.paths();

        let vaults = LocalAccount::list_local_folders(&paths, false).await?;
        let existing_name =
            vaults.iter().find(|(s, _)| s.name() == folder_name);

        let vault_passphrase =
            self.account.user()?.generate_folder_password()?;

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
        let (event, summary) = {
            let storage = self.account.storage()?;
            let mut writer = storage.write().await;
            let key: AccessKey = vault_passphrase.clone().into();
            writer.import_vault(buffer, Some(&key)).await?
        };

        self.account
            .user_mut()?
            .save_folder_password(vault.id(), vault_passphrase.clone().into())
            .await?;

        Ok((Event::Write(*summary.id(), event), summary))
    }
}
