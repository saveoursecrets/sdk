use anyhow::Result;
use secrecy::SecretString;
use sos_net::sdk::prelude::*;

use crate::test_utils::{setup, teardown};

const TEST_ID: &str = "security_report";

#[tokio::test]
async fn integration_security_report() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
    )
    .await?;

    let key: AccessKey = password.clone().into();
    account.sign_in(&key).await?;
    let summary = account.default_folder().await.unwrap();

    // Make changes to generate data
    let mock_ids = simulate_session(&mut account, &summary, password).await?;

    let report_options = SecurityReportOptions {
        excludes: vec![],
        database_handler: Some(|hashes: Vec<String>| async move {
            hashes.into_iter().map(|_| true).collect()
        }),
        target: None,
    };

    let report = account
        .generate_security_report::<bool, _, _>(report_options)
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
    let field_record = report
        .records
        .iter()
        .find(|r| {
            r.secret_id == mock_ids.field_id.0
                && r.field_id == Some(mock_ids.field_id.1)
        })
        .unwrap();

    assert!(weak_record.entropy.as_ref().unwrap().score() < 3);
    assert!(strong_record.entropy.as_ref().unwrap().score() >= 3);
    assert!(field_record.entropy.as_ref().unwrap().score() >= 3);

    // Delete the account
    account.delete_account().await?;

    teardown(TEST_ID).await;

    Ok(())
}

struct MockSecretIds {
    weak_id: SecretId,
    strong_id: SecretId,
    field_id: (SecretId, SecretId),
}

async fn simulate_session(
    account: &mut LocalAccount,
    default_folder: &Summary,
    _passphrase: SecretString,
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

    let (weak_id, _, _, _) = account
        .create_secret(weak_meta, weak_secret, default_folder.clone().into())
        .await?;

    // Create a password custom field.
    let field_id = SecretId::new_v4();
    let (password, _) = generate_passphrase()?;
    let field_secret = Secret::Password {
        password,
        name: None,
        user_data: Default::default(),
    };
    let field_meta =
        SecretMeta::new("Field password".to_string(), field_secret.kind());
    let mut user_data: UserData = Default::default();
    user_data.fields_mut().push(SecretRow::new(
        field_id,
        field_meta,
        field_secret,
    ));

    // Create a strong account secret
    let (password, _) = generate_passphrase()?;
    let strong_secret = Secret::Account {
        account: "string@example.com".to_string(),
        password,
        url: None,
        user_data,
    };
    let strong_meta =
        SecretMeta::new("Strong password".to_string(), strong_secret.kind());

    let (strong_id, _, _, _) = account
        .create_secret(
            strong_meta,
            strong_secret,
            default_folder.clone().into(),
        )
        .await?;

    Ok(MockSecretIds {
        weak_id,
        strong_id,
        field_id: (strong_id, field_id),
    })
}
