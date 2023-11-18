use anyhow::Result;

use secrecy::SecretString;
use serial_test::serial;

use sos_net::{
    client::user::{SecurityReportOptions, UserStorage},
    sdk::{
        passwd::diceware::generate_passphrase,
        storage::AppPaths,
        vault::{
            secret::{Secret, SecretId, SecretMeta, SecretRow, UserData},
            Summary,
        },
    },
};

use crate::test_utils::{create_local_account, setup};

#[tokio::test]
#[serial]
async fn integration_security_report() -> Result<()> {
    let dirs = setup(1).await?;

    let test_data_dir = dirs.clients.get(0).unwrap();
    AppPaths::set_data_dir(test_data_dir.clone());
    assert_eq!(AppPaths::data_dir()?, test_data_dir.clone().join("debug"));
    AppPaths::scaffold().await?;

    let (mut owner, _, summary, passphrase) =
        create_local_account("security_report").await?;

    // Make changes to generate data
    let mock_ids = simulate_session(&mut owner, &summary, passphrase).await?;

    let report_options = SecurityReportOptions {
        excludes: vec![],
        database_handler: Some(|hashes: Vec<String>| async move {
            hashes.into_iter().map(|_| true).collect()
        }),
        target: None,
    };

    let report = owner
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
    owner.delete_account().await?;

    // Reset the cache dir so we don't interfere
    // with other tests
    AppPaths::clear_data_dir();

    Ok(())
}

struct MockSecretIds {
    weak_id: SecretId,
    strong_id: SecretId,
    field_id: (SecretId, SecretId),
}

async fn simulate_session(
    owner: &mut UserStorage,
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

    let (weak_id, _) = owner
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

    let (strong_id, _) = owner
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
