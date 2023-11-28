//! Support for importing and exporting account contacts.
use crate::{
    account::{password::DelegatedPassword, Account, AccountsList},
    events::{AuditData, AuditEvent, EventKind},
    vault::{
        secret::{Secret, SecretId, SecretMeta},
        Gatekeeper, Summary,
    },
    vfs, Error, Result,
};
use std::path::Path;

/// Progress event when importing contacts.
pub enum ContactImportProgress {
    /// Progress event when the number of contacts is known.
    Ready {
        /// Total number of contacts.
        total: usize,
    },
    /// Progress event when a contact is being imported.
    Item {
        /// Label of the contact.
        label: String,
        /// Index of the contact.
        index: usize,
    },
}

impl<D> Account<D> {
    /// Try to load an avatar JPEG image for a contact.
    ///
    /// Looks in the current open folder if no specified folder is given.
    pub async fn load_avatar(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<Option<Vec<u8>>> {
        let (data, _) = self.read_secret(secret_id, folder).await?;
        if let Secret::Contact { vcard, .. } = &data.secret {
            let jpeg = if let Ok(mut jpegs) = vcard.parse_photo_jpeg() {
                if !jpegs.is_empty() {
                    Some(jpegs.remove(0))
                } else {
                    None
                }
            } else {
                None
            };
            return Ok(jpeg);
        }
        Ok(None)
    }

    /// Export a contact secret to a vCard file.
    pub async fn export_contact<P: AsRef<Path>>(
        &mut self,
        path: P,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<()> {
        let current_folder = {
            let storage = self.storage()?;
            let reader = storage.read().await;
            folder
                .as_ref()
                .or_else(|| reader.current().map(|g| g.summary()))
                .ok_or(Error::NoOpenFolder)?
                .clone()
        };

        let (data, _) = self.get_secret(secret_id, folder, false).await?;
        if let Secret::Contact { vcard, .. } = &data.secret {
            let content = vcard.to_string();
            vfs::write(&path, content).await?;
        } else {
            return Err(Error::NotContact);
        }

        let audit_event = AuditEvent::new(
            EventKind::ExportContacts,
            self.address().clone(),
            Some(AuditData::Secret(*current_folder.id(), *secret_id)),
        );
        self.append_audit_logs(vec![audit_event]).await?;

        Ok(())
    }

    /// Export all contacts to a single vCard.
    pub async fn export_all_contacts<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<()> {
        let local_accounts = AccountsList::new(&self.paths);

        let contacts = self
            .contacts_folder()
            .await
            .ok_or_else(|| Error::NoContactsFolder)?;

        let contacts_passphrase = DelegatedPassword::find_folder_password(
            self.user()?.identity().keeper(),
            contacts.id(),
        )
        .await?;
        let (vault, _) = local_accounts
            .find_local_vault(contacts.id(), false)
            .await?;
        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(contacts_passphrase.into()).await?;

        let mut vcf = String::new();
        let keys: Vec<&SecretId> = keeper.vault().keys().collect();
        for key in keys {
            if let Some((_, Secret::Contact { vcard, .. }, _)) =
                keeper.read(key).await?
            {
                vcf.push_str(&vcard.to_string());
            }
        }
        vfs::write(path, vcf.as_bytes()).await?;

        let audit_event = AuditEvent::new(
            EventKind::ExportContacts,
            self.address().clone(),
            None,
        );
        self.append_audit_logs(vec![audit_event]).await?;

        Ok(())
    }

    /// Import contacts from a vCard string buffer.
    pub async fn import_contacts(
        &mut self,
        content: &str,
        progress: impl Fn(ContactImportProgress),
    ) -> Result<Vec<SecretId>> {
        use crate::vcard4::parse;

        let mut ids = Vec::new();
        let current = {
            let storage = self.storage()?;
            let reader = storage.read().await;
            reader.current().map(|g| g.summary().clone())
        };

        let contacts = self
            .contacts_folder()
            .await
            .ok_or_else(|| Error::NoContactsFolder)?;
        self.open_vault(&contacts, false).await?;

        let cards = parse(content)?;

        progress(ContactImportProgress::Ready { total: cards.len() });

        for (index, vcard) in cards.into_iter().enumerate() {
            let label = vcard
                .formatted_name
                .get(0)
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_default();
            let secret = Secret::Contact {
                vcard: Box::new(vcard),
                user_data: Default::default(),
            };

            progress(ContactImportProgress::Item {
                label: label.clone(),
                index,
            });

            let meta = SecretMeta::new(label, secret.kind());
            let (id, _, _, _) =
                self.create_secret(meta, secret, Default::default()).await?;
            ids.push(id);
        }

        if let Some(folder) = current {
            self.open_vault(&folder, false).await?;
        }

        let audit_event = AuditEvent::new(
            EventKind::ImportContacts,
            self.address().clone(),
            None,
        );
        self.append_audit_logs(vec![audit_event]).await?;
        Ok(ids)
    }
}
