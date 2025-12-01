use anyhow::Result;
use secrecy::SecretString;
use sos_account::{Account, LocalAccount};
use sos_backend::BackendTarget;
use sos_core::crypto::AccessKey;
use sos_database::entity::{AccountEntity, AccountRecord};
use sos_password::diceware::generate_passphrase;
use sos_vault::Summary;

mod shared_folder;

async fn prepare_local_db_account(
    target: &BackendTarget,
    name: &str,
) -> Result<(AccountRecord, LocalAccount, Summary, SecretString)> {
    assert!(
        matches!(target, BackendTarget::Database(_, _)),
        "must be a database target"
    );
    let account_name = name.to_string();
    let (password, _) = generate_passphrase()?;
    let mut account = LocalAccount::new_account_with_builder(
        account_name.to_owned(),
        password.clone(),
        target.clone(),
        |builder| {
            builder
                .save_passphrase(false)
                .create_archive(true)
                .create_authenticator(false)
                .create_contacts(true)
                .create_file_password(true)
        },
    )
    .await?;

    let key: AccessKey = password.clone().into();
    account.sign_in(&key).await?;
    let summary = account.default_folder().await.unwrap();

    let BackendTarget::Database(_, client) = target else {
        unreachable!();
    };
    let account_id = *account.account_id();
    let account_record: AccountRecord = client
        .conn_and_then(move |conn| {
            let entity = AccountEntity::new(&conn);
            let account_row = entity.find_one(&account_id)?;
            Ok::<_, anyhow::Error>(account_row.try_into().unwrap())
        })
        .await?;

    Ok((account_record, account, summary, password))
}
