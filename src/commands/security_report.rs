use std::{fmt, str::FromStr, path::PathBuf};
use sos_net::{
    client::{provider::ProviderFactory, user::{SecurityReportOptions, SecurityReportRow}, hashcheck},
    sdk::account::AccountRef,
};

use crate::{
    helpers::{
        account::resolve_user,
    },
    Error, Result,
};

/// Formats for writing reports.
#[derive(Default, Debug, Clone)]
pub enum SecurityReportFormat {
    /// CSV output format.
    #[default]
    Csv,
    /// JSON output format.
    Json,
}

impl fmt::Display for SecurityReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::Csv => "csv",
            Self::Json => "json",
        })
    }
}

impl FromStr for SecurityReportFormat {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "csv" => Ok(Self::Csv),
            "json" => Ok(Self::Json),
            _ => Err(Error::UnknownReportFormat(s.to_owned())),
        }
    }
}

pub async fn run(
    account: Option<AccountRef>,
    force: bool,
    format: SecurityReportFormat,
    path: PathBuf,
    factory: ProviderFactory,
) -> Result<()> {
    if tokio::fs::try_exists(&path).await? && !force {
        return Err(Error::FileExistsUseForce(path));
    }

    let user = resolve_user(account.as_ref(), factory, false).await?;
    let mut owner = user.write().await;

    let report_options = SecurityReportOptions { 
        excludes: vec![],
        database_handler: Some(
            |hashes: Vec<String>| async move {
                match hashcheck::batch(&hashes, None).await {
                    Ok(res) => res,
                    Err(_) => hashes.into_iter().map(|_| false).collect(),
                }
            },
        ),
    };
    let report =
        owner
            .generate_security_report::<bool, _, _>(
                report_options,
            )
            .await?;

    let rows: Vec<SecurityReportRow<bool>> = report.into();

    match format {
        SecurityReportFormat::Csv => {
            let mut out = csv_async::AsyncSerializer::from_writer(
                tokio::fs::File::create(&path).await?
            );
            for row in rows {
                out.serialize(&row).await?;
            }
        }
        SecurityReportFormat::Json => {
            let mut out = std::fs::File::create(&path)?;
            serde_json::to_writer_pretty(&mut out, &rows)?;
        }
    }

    tracing::info!(path = ?path, "wrote security report");

    Ok(())
}
