use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::migrate::{
    import::{ImportFormat, ImportTarget},
    LocalImport,
};
use sos_net::sdk::{
    account::{LocalAccount, UserPaths},
    passwd::diceware::generate_passphrase,
};
use std::path::PathBuf;

const TEST_ID: &str = "migrate_import";

/// Tests importing plain text secrets from other apps.
#[tokio::test]
async fn integration_migrate_import() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    UserPaths::scaffold(Some(data_dir.clone())).await?;
    UserPaths::new_global(data_dir.clone());

    let (mut account, _new_account) = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    account.sign_in(password.clone()).await?;

    let target = ImportTarget {
        format: ImportFormat::OnePasswordCsv,
        path: PathBuf::from(
            "workspace/migrate/fixtures/1password-export.csv",
        ),
        folder_name: "1password".to_string(),
    };
    let mut importer = LocalImport::new(&mut account);
    importer.import_file(target).await?;

    let folder = account.find(|s| s.name() == "1password").await;
    assert!(folder.is_some());

    let target = ImportTarget {
        format: ImportFormat::DashlaneZip,
        path: PathBuf::from("workspace/migrate/fixtures/dashlane-export.zip"),
        folder_name: "dashlane".to_string(),
    };
    let mut importer = LocalImport::new(&mut account);
    importer.import_file(target).await?;

    let folder = account.find(|s| s.name() == "dashlane").await;
    assert!(folder.is_some());

    let target = ImportTarget {
        format: ImportFormat::BitwardenCsv,
        path: PathBuf::from(
            "workspace/migrate/fixtures/bitwarden-export.csv",
        ),
        folder_name: "bitwarden".to_string(),
    };
    let mut importer = LocalImport::new(&mut account);
    importer.import_file(target).await?;

    let folder = account.find(|s| s.name() == "bitwarden").await;
    assert!(folder.is_some());

    let target = ImportTarget {
        format: ImportFormat::ChromeCsv,
        path: PathBuf::from("workspace/migrate/fixtures/chrome-export.csv"),
        folder_name: "chrome".to_string(),
    };
    let mut importer = LocalImport::new(&mut account);
    importer.import_file(target).await?;

    let folder = account.find(|s| s.name() == "chrome").await;
    assert!(folder.is_some());

    let target = ImportTarget {
        format: ImportFormat::FirefoxCsv,
        path: PathBuf::from("workspace/migrate/fixtures/firefox-export.csv"),
        folder_name: "firefox".to_string(),
    };
    let mut importer = LocalImport::new(&mut account);
    importer.import_file(target).await?;

    let folder = account.find(|s| s.name() == "firefox").await;
    assert!(folder.is_some());

    let target = ImportTarget {
        format: ImportFormat::MacosCsv,
        path: PathBuf::from("workspace/migrate/fixtures/macos-export.csv"),
        folder_name: "macos".to_string(),
    };
    let mut importer = LocalImport::new(&mut account);
    importer.import_file(target).await?;

    let folder = account.find(|s| s.name() == "macos").await;
    assert!(folder.is_some());

    teardown(TEST_ID).await;

    Ok(())
}
