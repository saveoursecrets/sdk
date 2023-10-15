//! Generate a security report for all passwords.

use crate::client::{user::UserStorage, Result};
use futures::Future;
use serde::{Deserialize, Serialize};
use sos_sdk::vault::{
    secret::{Secret, SecretId, SecretType},
    Summary, VaultId,
};
use std::pin::Pin;

/// Options for security report generation.
pub struct SecurityReportOptions<T> {
    /// Exclude these folders from report generation.
    pub excludes: Vec<VaultId>,
    /// Handler that accepts a list of SHA-1 hashes of the passwords
    /// and can perform a check to see if they exist in a
    /// database of breached passwords.
    pub database_handler:
        Box<dyn Fn(Vec<Vec<u8>>) -> Pin<Box<dyn Future<Output = Vec<T>>>>>,
}

/// List of records for a generated security report.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityReport<T> {
    /// Report row records.
    pub records: Vec<SecurityReportRecord>,
    /// Caller reports.
    pub database_checks: Vec<T>,
}

/// Security report record.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityReportRecord {
    /// Vault identifier.
    pub vault_id: VaultId,
    /// Secret identifier.
    pub secret_id: SecretId,
    /// Owner information when the password
    /// belongs to a parent secret (custom field).
    pub owner: Option<(SecretId, usize)>,
    /// Report on password entropy and user defined
    /// reporting information (eg: haveibeenpwned lookup).
    #[serde(flatten)]
    pub report: PasswordReport,
}

/// Password report.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordReport {
    /// The entropy score.
    pub score: u8,
    /// The estimated number of guesses needed to crack the password.
    pub guesses: u64,
    /// The order of magnitude of guesses.
    pub guesses_log10: f64,
}

impl UserStorage {
    /// Generate a security report.
    pub async fn generate_security_report<T>(
        &mut self,
        options: SecurityReportOptions<T>,
    ) -> Result<SecurityReport<T>> {
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

                let report = PasswordReport {
                    score: entropy.score(),
                    guesses: entropy.guesses(),
                    guesses_log10: entropy.guesses_log10(),
                };

                let record = SecurityReportRecord {
                    vault_id: *vault.id(),
                    secret_id,
                    owner,
                    report,
                };

                hashes.push(sha1);
                records.push(record);
            }
        }

        // Restore the original open vault
        if let Some(current) = current {
            self.open_vault(&current, false).await?;
        }

        let database_checks = (options.database_handler)(hashes).await;
        Ok(SecurityReport {
            records,
            database_checks,
        })
    }
}
