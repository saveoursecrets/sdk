//! Generate a security report for all passwords.

use crate::client::{user::UserStorage, Result};
use serde::{Deserialize, Serialize};
use sos_sdk::{
    vault::{
        secret::{Secret, SecretId, SecretType},
        Summary, VaultId,
    },
    zxcvbn::Entropy,
};

/// Options for security report generation.
pub struct SecurityReportOptions<T, H, F>
where
    H: Fn(Vec<Vec<u8>>) -> F,
    F: std::future::Future<Output = Vec<T>>,
{
    /// Exclude these folders from report generation.
    pub excludes: Vec<VaultId>,
    /// Database handler that can check for breaches
    /// based on the password hashes (SHA-1).
    ///
    /// The handler is passed a list of passwords hashes 
    /// and must return a list of `T` the same length as 
    /// the input.
    pub database_handler: Option<H>,
}

/// List of records for a generated security report.
pub struct SecurityReport<T> {
    /// Report row records.
    pub records: Vec<SecurityReportRecord>,
    /// Caller reports.
    pub database_checks: Vec<T>,
}

/// Security report record.
pub struct SecurityReportRecord {
    /// Folder summary.
    pub folder: Summary,
    /// Secret identifier.
    pub secret_id: SecretId,
    /// Owner information when the password
    /// belongs to a parent secret (custom field).
    pub owner: Option<(SecretId, usize)>,
    /// Password entropy information.
    pub entropy: Entropy,
}

impl UserStorage {
    /// Generate a security report.
    pub async fn generate_security_report<T, H, F>(
        &mut self,
        options: SecurityReportOptions<T, H, F>,
    ) -> Result<SecurityReport<T>>
    where
        H: Fn(Vec<Vec<u8>>) -> F,
        F: std::future::Future<Output = Vec<T>>,
    {
        let mut records = Vec::new();
        let mut hashes = Vec::new();
        let folders = self.list_folders().await?;
        let targets: Vec<Summary> = folders
            .into_iter()
            .filter(|folder| !options.excludes.contains(folder.id()))
            .collect();

        // Store current open vault so we can restore afterwards
        let current = self
            .storage
            .current()
            .map(|keeper| keeper.vault().summary().clone());

        for target in targets {
            self.open_vault(&target, false).await?;

            let keeper = self.storage.current().unwrap();
            let vault = keeper.vault();
            let mut password_hashes = Vec::new();
            for secret_id in vault.keys() {
                if let Some((_meta, secret, _)) =
                    keeper.read(secret_id).await?
                {
                    for (index, field) in
                        secret.user_data().fields().iter().enumerate()
                    {
                        if field.meta().kind() == &SecretType::Account
                            || field.meta().kind() == &SecretType::Password
                        {
                            let check =
                                Secret::check_password(field.secret())?;
                            if let Some(check) = check {
                                password_hashes.push((
                                    *field.id(),
                                    check,
                                    Some((*secret_id, index)),
                                ));
                            }
                        }
                    }

                    let check = Secret::check_password(&secret)?;
                    if let Some(check) = check {
                        password_hashes.push((*secret_id, check, None));
                    }
                }
            }

            for (secret_id, check, owner) in password_hashes {
                let (entropy, sha1) = check;

                let record = SecurityReportRecord {
                    folder: target.clone(),
                    secret_id,
                    owner,
                    entropy,
                };

                hashes.push(sha1);
                records.push(record);
            }
        }

        // Restore the original open vault
        if let Some(current) = current {
            self.open_vault(&current, false).await?;
        }

        let database_checks =
            if let Some(database_handler) = options.database_handler {
                (database_handler)(hashes).await
            } else {
                vec![]
            };
        Ok(SecurityReport {
            records,
            database_checks,
        })
    }
}
