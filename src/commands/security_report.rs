use sos_net::{
    reqwest,
    client::{provider::ProviderFactory, user::SecurityReportOptions, hashcheck},
    sdk::account::AccountRef,
};

use crate::{
    helpers::{
        account::resolve_user,
    },
    Result,
};

/// Formats for writing reports.
#[derive(Default)]
pub enum SecurityReportFormat {
    #[default]
    Json,
}

pub async fn run(
    account: Option<AccountRef>,
    format: SecurityReportFormat,
    factory: ProviderFactory,
) -> Result<()> {
    let user = resolve_user(account.as_ref(), factory, false).await?;
    let mut owner = user.write().await;

    let report_options = SecurityReportOptions { 
        excludes: vec![],
        database_handler: Some(
            |hashes: Vec<Vec<u8>>| async move {
                hashcheck::batch(hashes, None).await?
            },
        ),
    };
    let report =
        owner
            .generate_security_report::<bool, _, _>(
                report_options,
            )
            .await?;
    
    let contents = match format {
        SecurityReportFormat::Json => {
            serde_json::to_string_pretty(&report)?
        }
    };

    println!("{}", contents);

    Ok(())
}