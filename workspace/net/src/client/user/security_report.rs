//! Generate a security report for all passwords.
use crate::client::{user::UserStorage, Result};
use serde::{Deserialize, Serialize};
use sos_sdk::vault::{
    secret::{Secret, SecretId, SecretType},
    Summary, VaultId,
};

/// Options for security report generation.
pub struct SecurityReportOptions<T, H, F>
where
    H: Fn(Vec<String>) -> F,
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

/// Row for security report output.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityReportRow<T> {
    /// Folder name.
    pub folder_name: String,
    /// Folder identifier.
    pub folder_id: VaultId,
    /// Secret identifier.
    pub secret_id: SecretId,
    /// Owner secret identifier (when custom field).
    pub owner_id: Option<SecretId>,
    /// Field index (when custom field).
    pub field_index: Option<usize>,
    /// The entropy score.
    pub score: u8,
    /// The estimated number of guesses needed to crack the password.
    pub guesses: u64,
    /// The order of magnitude of guesses.
    pub guesses_log10: f64,
    /// Determines if the password is empty.
    pub is_empty: bool,
    /// Result of a database check.
    #[serde(rename = "breached")]
    pub database_check: T,
}

/// List of records for a generated security report.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityReport<T> {
    /// Report row records.
    pub records: Vec<SecurityReportRecord>,
    /// Caller reports.
    pub database_checks: Vec<T>,
}

impl<T> From<SecurityReport<T>> for Vec<SecurityReportRow<T>> {
    fn from(value: SecurityReport<T>) -> Self {
        let mut out = Vec::new();
        for (record, database_check) in value
            .records
            .into_iter()
            .zip(value.database_checks.into_iter())
        {
            out.push(SecurityReportRow {
                folder_name: record.folder.name().to_owned(),
                folder_id: *record.folder.id(),
                secret_id: record.secret_id,
                owner_id: record.owner.map(|(id, _)| id),
                field_index: record.owner.map(|(_, index)| index),
                score: record.report.score,
                guesses: record.report.guesses,
                guesses_log10: record.report.guesses_log10,
                is_empty: record.report.is_empty,
                database_check,
            });
        }
        out
    }
}

/// Security report record.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityReportRecord {
    /// Folder summary.
    pub folder: Summary,
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
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordReport {
    /// The entropy score.
    pub score: u8,
    /// The estimated number of guesses needed to crack the password.
    pub guesses: u64,
    /// The order of magnitude of guesses.
    pub guesses_log10: f64,
    /// Determines if the password is empty.
    pub is_empty: bool,
}

impl UserStorage {
    /// Generate a security report.
    pub async fn generate_security_report<T, H, F>(
        &mut self,
        options: SecurityReportOptions<T, H, F>,
    ) -> Result<SecurityReport<T>>
    where
        H: Fn(Vec<String>) -> F,
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

                let report = if let Some(entropy) = entropy {
                    PasswordReport {
                        score: entropy.score(),
                        guesses: entropy.guesses(),
                        guesses_log10: entropy.guesses_log10(),
                        is_empty: false,
                    }
                } else {
                    PasswordReport {
                        score: 0,
                        guesses: 0,
                        guesses_log10: 0.0,
                        is_empty: true,
                    }
                };

                let record = SecurityReportRecord {
                    folder: target.clone(),
                    secret_id,
                    owner,
                    report,
                };

                hashes.push(hex::encode(sha1));
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
