//! Adds security report functions to network account.
use crate::client::{NetworkAccount, Result};
use sos_sdk::account::security_report::{
    SecurityReport, SecurityReportOptions,
};

impl NetworkAccount {
    /// Generate a security report.
    pub async fn generate_security_report<T, D, R>(
        &mut self,
        options: SecurityReportOptions<T, D, R>,
    ) -> Result<SecurityReport<T>>
    where
        D: Fn(Vec<String>) -> R,
        R: std::future::Future<Output = Vec<T>>,
    {
        Ok(self.account.generate_security_report(options).await?)
    }
}
