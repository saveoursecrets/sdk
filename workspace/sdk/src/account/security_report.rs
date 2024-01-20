//! Types for security report generation.
use crate::{
    vault::{
        secret::{Secret, SecretId, SecretType},
        Gatekeeper, Summary, VaultId,
    },
    zxcvbn::Entropy,
    Result,
};
use serde::{Deserialize, Serialize};

/// Specific target for a security report.
pub struct SecurityReportTarget(
    pub VaultId,
    pub SecretId,
    pub Option<SecretId>,
);

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

    /// Target for report generation.
    ///
    /// This is useful when providing a UI to resolve
    /// security report issues and changes have been
    /// made; the caller can generate a new report
    /// for the changed item and decide if the item
    /// is now deemed safe.
    ///
    /// When a target is given excludes are ignored.
    pub target: Option<SecurityReportTarget>,
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
    /// Custom field identifier.
    pub field_id: Option<SecretId>,
    /// The entropy score.
    pub score: u8,
    /// The estimated number of guesses needed to crack the password.
    pub guesses: u64,
    /// The order of magnitude of guesses.
    pub guesses_log10: f64,
    /// Result of a database check.
    #[serde(rename = "breached")]
    pub database_check: T,
}

impl SecurityReportRow<bool> {
    /// Determine if this row is deemed to be secure.
    ///
    /// A report is deemed to be secure when the entropy
    /// score is greater than or equal to 3 and the password
    /// hash has not been detected as appearing in a database
    /// of breached passwords.
    pub fn is_secure(&self) -> bool {
        self.score >= 3 && !self.database_check
    }

    /// Determine if this row is deemed to be insecure.
    pub fn is_insecure(&self) -> bool {
        !self.is_secure()
    }
}

/// List of records for a generated security report.
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
            let score =
                record.entropy.as_ref().map(|e| e.score()).unwrap_or(0);
            let guesses =
                record.entropy.as_ref().map(|e| e.guesses()).unwrap_or(0);
            let guesses_log10 = record
                .entropy
                .as_ref()
                .map(|e| e.guesses_log10())
                .unwrap_or(0.0);

            out.push(SecurityReportRow {
                folder_name: record.folder.name().to_owned(),
                folder_id: *record.folder.id(),
                secret_id: record.secret_id,
                field_id: record.field_id,
                score,
                guesses,
                guesses_log10,
                database_check,
            });
        }
        out
    }
}

/// Security report record.
pub struct SecurityReportRecord {
    /// Folder summary.
    pub folder: Summary,
    /// Secret identifier.
    pub secret_id: SecretId,
    /// Field identifier when the password is a custom field.
    pub field_id: Option<SecretId>,
    /// Report on password entropy.
    ///
    /// Will be `None` when the password is empty.
    pub entropy: Option<Entropy>,
}

pub(super) async fn secret_security_report(
    secret_id: &SecretId,
    keeper: &Gatekeeper,
    password_hashes: &mut Vec<(
        SecretId,
        (Option<Entropy>, Vec<u8>),
        Option<SecretId>,
    )>,
    target_field: Option<&SecretId>,
) -> Result<()> {
    if let Some((_meta, secret, _)) = keeper.read_secret(secret_id).await? {
        for field in secret.user_data().fields().iter().filter(|field| {
            if let Some(field_id) = target_field {
                return field_id == field.id();
            }
            true
        }) {
            if field.meta().kind() == &SecretType::Account
                || field.meta().kind() == &SecretType::Password
            {
                let check = Secret::check_password(field.secret())?;
                if let Some(check) = check {
                    password_hashes.push((
                        *secret_id,
                        check,
                        Some(*field.id()),
                    ));
                }
            }
        }
        let check = Secret::check_password(&secret)?;
        if let Some(check) = check {
            password_hashes.push((*secret_id, check, None));
        }
    }
    Ok(())
}
