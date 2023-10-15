use anyhow::Result;

use secrecy::SecretString;
use serial_test::serial;
use std::path::{Path, PathBuf};

use sos_net::{
    client::{
        provider::ProviderFactory,
        user::{SecurityReportOptions, UserStorage},
    },
    migrate::import::ImportTarget,
};
use sos_sdk::{
    account::ImportedAccount,
    passwd::diceware::generate_passphrase,
    storage::AppPaths,
    vault::{
        secret::{Secret, SecretId, SecretMeta},
        Summary,
    },
    vfs::{self, File},
};

use crate::test_utils::setup;

#[tokio::test]
#[serial]
async fn integration_security_report() -> Result<()> {
    let dirs = setup(1).await?;

    let test_data_dir = dirs.clients.get(0).unwrap();
    AppPaths::set_data_dir(test_data_dir.clone());
    assert_eq!(AppPaths::data_dir()?, test_data_dir.clone().join("debug"));
    AppPaths::scaffold().await?;

    let account_name = "Security report test".to_string();
    let (passphrase, _) = generate_passphrase()?;
    let factory = ProviderFactory::Local(None);
    let (mut owner, imported_account, _) =
        UserStorage::new_account_with_builder(
            account_name.clone(),
            passphrase.clone(),
            factory.clone(),
            |builder| {
                builder
                    .save_passphrase(false)
                    .create_archive(true)
                    .create_authenticator(false)
                    .create_contacts(true)
                    .create_file_password(false)
            },
        )
        .await?;

    let ImportedAccount { summary, .. } = imported_account;

    owner.initialize_search_index().await?;

    // Make changes to generate data
    let mock_ids = simulate_session(&mut owner, &summary, passphrase).await?;

    let report_options = SecurityReportOptions { excludes: vec![] };
    let report =
        owner
            .generate_security_report::<bool, _, _>(
                report_options,
                |hashes| async move {
                    hashes.into_iter().map(|hash| true).collect()
                },
            )
            .await?;

    let weak_record = report
        .records
        .iter()
        .find(|r| r.secret_id == mock_ids.weak_id)
        .unwrap();
    let strong_record = report
        .records
        .iter()
        .find(|r| r.secret_id == mock_ids.strong_id)
        .unwrap();

    assert!(weak_record.report.score < 3);
    assert!(strong_record.report.score >= 3);

    // Delete the account
    owner.delete_account().await?;

    // Reset the cache dir so we don't interfere
    // with other tests
    AppPaths::clear_data_dir();

    Ok(())
}

struct MockSecretIds {
    weak_id: SecretId,
    strong_id: SecretId,
}

async fn simulate_session(
    owner: &mut UserStorage,
    default_folder: &Summary,
    passphrase: SecretString,
) -> Result<MockSecretIds> {
    // Create a weak account secret
    let weak_secret = Secret::Account {
        account: "weak@example.com".to_string(),
        password: secrecy::SecretString::new("test".to_string()),
        url: None,
        user_data: Default::default(),
    };
    let weak_meta =
        SecretMeta::new("Weak password".to_string(), weak_secret.kind());

    let (weak_id, _) = owner
        .create_secret(weak_meta, weak_secret, default_folder.clone().into())
        .await?;

    // Create a strong account secret
    let (password, _) = generate_passphrase()?;
    let strong_secret = Secret::Account {
        account: "string@example.com".to_string(),
        password,
        url: None,
        user_data: Default::default(),
    };
    let strong_meta =
        SecretMeta::new("Strong password".to_string(), strong_secret.kind());

    let (strong_id, _) = owner
        .create_secret(
            strong_meta,
            strong_secret,
            default_folder.clone().into(),
        )
        .await?;

    Ok(MockSecretIds { weak_id, strong_id })
}