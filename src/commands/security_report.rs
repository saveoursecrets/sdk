//use human_bytes::human_bytes;
use sos_net::{
    client::{provider::ProviderFactory, user::SecurityReportOptions},
    sdk::account::AccountRef,
};

use crate::{
    helpers::{
        account::resolve_user,
    },
    Result,
};

pub async fn run(
    account: Option<AccountRef>,
    factory: ProviderFactory,
) -> Result<()> {
    let user = resolve_user(account.as_ref(), factory, false).await?;
    let mut owner = user.write().await;

    let report_options = SecurityReportOptions { 
        excludes: vec![],
        database_handler: Some(
            |hashes: Vec<Vec<u8>>| async move {
                hashes.into_iter().map(|_| true).collect()
            },
        ),
    };
    let report =
        owner
            .generate_security_report::<bool, _, _>(
                report_options,
            )
            .await?;

    println!("{:#?}", report);

    Ok(())
}
