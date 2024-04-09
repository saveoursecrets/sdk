//! Convert account data.
use crate::{account::Account, crypto::Cipher};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Conversion paths for a folder.
#[derive(Debug, Serialize, Deserialize)]
pub struct FolderConversion {
    cipher: Cipher,
    vault: PathBuf,
    events: PathBuf,
}

/// Conversion paths for an account.
#[derive(Debug, Serialize, Deserialize)]
pub struct CipherConversion {
    /// Identity folder conversion info.
    pub identity: Option<FolderConversion>,
    /// User folders conversion info.
    pub folders: Vec<FolderConversion>,
}

/// Convert the cipher in use by an account.
pub struct ConvertCipher;

impl ConvertCipher {
    /// Build list of files to convert.
    pub async fn build<'a, A>(
        account: &'a A,
        cipher: &Cipher,
    ) -> std::result::Result<CipherConversion, A::Error>
    where
        A: Account,
    {
        let identity = account.identity_folder_summary().await?;
        let folders = account
            .list_folders()
            .await?
            .into_iter()
            .filter(|s| s.cipher() != cipher)
            .map(|s| FolderConversion {
                cipher: s.cipher().clone(),
                vault: account.paths().vault_path(s.id()),
                events: account.paths().event_log_path(s.id()),
            })
            .collect::<Vec<_>>();

        let identity = if cipher != identity.cipher() {
            Some(FolderConversion {
                cipher: identity.cipher().clone(),
                vault: account.paths().identity_vault(),
                events: account.paths().identity_events(),
            })
        } else {
            None
        };

        Ok(CipherConversion { identity, folders })
    }
}
