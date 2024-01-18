use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;
use std::path::PathBuf;

/// Tests importing plain text secrets from other apps.
#[tokio::test]
async fn integration_migrate_import() -> Result<()> {
    const TEST_ID: &str = "migrate_import";
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

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

    let target = ImportTarget {
        format: ImportFormat::OnePasswordCsv,
        path: PathBuf::from("tests/fixtures/migrate/1password-export.csv"),
        folder_name: "1password".to_string(),
    };
    account.import_file(target).await?;

    let folder = account.find(|s| s.name() == "1password").await;
    assert!(folder.is_some());

    let target = ImportTarget {
        format: ImportFormat::DashlaneZip,
        path: PathBuf::from("tests/fixtures/migrate/dashlane-export.zip"),
        folder_name: "dashlane".to_string(),
    };
    account.import_file(target).await?;

    let folder = account.find(|s| s.name() == "dashlane").await;
    assert!(folder.is_some());

    let target = ImportTarget {
        format: ImportFormat::BitwardenCsv,
        path: PathBuf::from("tests/fixtures/migrate/bitwarden-export.csv"),
        folder_name: "bitwarden".to_string(),
    };
    account.import_file(target).await?;

    let folder = account.find(|s| s.name() == "bitwarden").await;
    assert!(folder.is_some());

    let target = ImportTarget {
        format: ImportFormat::ChromeCsv,
        path: PathBuf::from("tests/fixtures/migrate/chrome-export.csv"),
        folder_name: "chrome".to_string(),
    };
    account.import_file(target).await?;

    let folder = account.find(|s| s.name() == "chrome").await;
    assert!(folder.is_some());

    let target = ImportTarget {
        format: ImportFormat::FirefoxCsv,
        path: PathBuf::from("tests/fixtures/migrate/firefox-export.csv"),
        folder_name: "firefox".to_string(),
    };
    account.import_file(target).await?;

    let folder = account.find(|s| s.name() == "firefox").await;
    assert!(folder.is_some());

    let target = ImportTarget {
        format: ImportFormat::MacosCsv,
        path: PathBuf::from("tests/fixtures/migrate/macos-export.csv"),
        folder_name: "macos".to_string(),
    };
    account.import_file(target).await?;

    let folder = account.find(|s| s.name() == "macos").await;
    assert!(folder.is_some());

    teardown(TEST_ID).await;

    Ok(())
}
