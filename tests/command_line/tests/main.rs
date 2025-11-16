use anticipate_runner::{InterpreterOptions, ScriptFile};
use anyhow::Result;
use sos_core::Paths;
use sos_database::{migrations::migrate_client, open_file};
use std::{
    env::{set_var, var},
    path::Path,
};

#[tokio::test]
async fn command_line() -> Result<()> {
    prepare_env().await?;

    let specs = vec![
        "scripts/setup.sh",
        "scripts/specs/account.sh",
        "scripts/specs/check.sh",
        "scripts/specs/device.sh",
        "scripts/specs/environment.sh",
        "scripts/specs/events.sh",
        "scripts/specs/folder.sh",
        "scripts/specs/secret.sh",
        "scripts/specs/security-report.sh",
        "scripts/specs/server.sh",
        "scripts/specs/shell.sh",
        "scripts/specs/preferences.sh",
        "scripts/specs/audit.sh",
        "scripts/teardown.sh",
    ];

    for spec in specs {
        run_spec(spec)?;
    }

    Ok(())
}

fn run_spec(input_file: impl AsRef<Path>) -> Result<()> {
    println!("run_spec: {:#?}", input_file.as_ref());

    let file_name = input_file
        .as_ref()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let echo = var("ANTICIPATE_ECHO").ok().is_some();
    let script = ScriptFile::parse(input_file)?;
    let mut options = InterpreterOptions::new(15000, echo, false, false);
    options.id = Some(file_name.to_owned());
    script.run(options)?;
    Ok(())
}

async fn prepare_env() -> Result<()> {
    let path = var("PATH").ok().unwrap_or_default();
    let prefix = "target/debug";
    set_var("PATH", format!("{}:{}", prefix, path));

    let data_dir = std::env::current_dir()?
        .join("../../target/accounts")
        .canonicalize()?;

    println!("prepare_env: {:#?}", data_dir);

    if var("SOS_TEST_CLIENT_DB").ok().is_some() {
        let paths = Paths::new_client(&data_dir);
        let db = paths.database_file().to_owned();
        let mut client = open_file(&db).await?;
        let report = migrate_client(&mut client).await?;
        let migrations = report.applied_migrations();
        for migration in migrations {
            println!(
                "Migration      {} v{}",
                migration.name(),
                migration.version(),
            );
        }
    }

    set_var("BASH_SILENCE_DEPRECATION_WARNING", "1");
    set_var("NO_COLOR", "1");

    set_var("SOS_DATA_DIR", data_dir.to_string_lossy().as_ref());
    set_var("SOS_PROMPT", "➜ ");
    set_var("SOS_OFFLINE", "1");
    set_var("DEMO_SERVER", "http://demo.saveoursecrets.co:5053");

    set_var("ACCOUNT_NAME", "Demo");
    set_var("ACCOUNT_NAME_ALT", "Demo Account");
    set_var("ACCOUNT_PASSWORD", "demo-test-password-case");
    set_var("ACCOUNT_BACKUP", "../../target/demo/backup.zip");
    set_var("ACCOUNT_CONTACTS", "../fixtures/contacts.vcf");
    set_var("CONTACTS_EXPORT", "../../target/demo/contacts.vcf");

    set_var("DEFAULT_FOLDER_NAME", "Documents");
    set_var("FOLDER_NAME", "mock-folder");
    set_var("NEW_FOLDER_NAME", "mock-folder-renamed");

    set_var("FILE_INPUT", "../fixtures/sample.heic");
    set_var("FILE_OUTPUT", "../../target/demo/file-download.heic");

    set_var("ATTACH_INPUT", "../fixtures/test-file.txt");
    set_var("ATTACH_OUTPUT", "../../target/demo/attachment-download.txt");

    set_var("NOTE_NAME", "mock note");
    set_var("FILE_NAME", "mock file");
    set_var("LOGIN_NAME", "mock login");
    set_var("LIST_NAME", "mock list");

    set_var("LOGIN_SERVICE_NAME", "mock-service");
    set_var("LOGIN_URL", "https://example.com");
    set_var("LOGIN_PASSWORD", "mock-login-password");

    set_var("LIST_NAME", "mock-list");
    set_var("LIST_KEY_1", "SERVICE_1_API");
    set_var("LIST_VALUE_1", "mock-key-1");
    set_var("LIST_KEY_2", "SERVICE_2_API");
    set_var("LIST_VALUE_2", "mock-key-2");

    set_var("FILE_ATTACHMENT", "file-attachment");
    set_var("NOTE_ATTACHMENT", "note-attachment");
    set_var("LINK_ATTACHMENT", "link-attachment");
    set_var("PASSWORD_ATTACHMENT", "password-attachment");
    set_var("LINK_VALUE", "https://example.com");

    set_var("MIGRATE_EXPORT", "../../target/demo/export.zip");
    set_var(
        "MIGRATE_1PASSWORD",
        "../fixtures/migrate/1password-export.csv",
    );
    set_var(
        "MIGRATE_DASHLANE",
        "../fixtures/migrate/dashlane-export.zip",
    );
    set_var(
        "MIGRATE_BITWARDEN",
        "../fixtures/migrate/bitwarden-export.csv",
    );
    set_var("MIGRATE_FIREFOX", "../fixtures/migrate/firefox-export.csv");
    set_var("MIGRATE_MACOS", "../fixtures/migrate/macos-export.csv");

    set_var("SECURITY_REPORT_CSV", "../../target/demo/report.csv");

    Ok(())
}

pub use sos_test_utils as test_utils;
