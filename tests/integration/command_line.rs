use anyhow::Result;
use serial_test::serial;
use std::path::PathBuf;

use sos_sdk::{
    passwd::diceware::generate_passphrase, secrecy::ExposeSecret,
    signer::ecdsa::Address, storage::StorageDirs,
};

use sos_net::migrate::import::ImportFormat;

use secrecy::SecretString;

use rexpect::{spawn, ReadUntil};

const ACCOUNT_NAME: &str = "mock-account";
const NEW_NAME: &str = "mock-account-renamed";
const TIMEOUT: Option<u64> = Some(30000);

fn is_coverage() -> bool {
    env_is_set("COVERAGE") && env_is_set("COVERAGE_BINARIES")
}

fn is_ci() -> bool {
    env_is_set("CI")
}

fn env_is_set(name: &str) -> bool {
    std::env::var(name).is_ok() && !std::env::var(name).unwrap().is_empty()
}

#[test]
#[serial]
fn integration_command_line() -> Result<()> {
    let (password, _) = generate_passphrase()?;

    let cache_dir = PathBuf::from("target/command_line_test");
    if cache_dir.exists() {
        std::fs::remove_dir_all(&cache_dir)?;
    }
    std::fs::create_dir_all(&cache_dir)?;

    let cache_dir = cache_dir.canonicalize()?;
    // Set cache directory for child processes
    std::env::set_var("SOS_CACHE", cache_dir.clone());
    // Set so test functions can access
    StorageDirs::set_cache_dir(cache_dir);

    if is_ci() {
        std::env::set_var("SOS_YES", true.to_string());
        std::env::set_var(
            "SOS_PASSWORD",
            password.expose_secret().to_owned(),
        );
    }

    let exe = if is_coverage() {
        PathBuf::from(std::env::var("COVERAGE_BINARIES")?)
            .join("sos")
            .to_string_lossy()
            .into_owned()
    } else {
        "target/debug/sos".to_owned()
    };

    account_new(&exe, &password)?;
    let address = account_list(&exe)?;
    account_backup_restore(&exe, &address, &password)?;
    account_info(&exe, &address, &password)?;
    account_rename(&exe, &address, &password)?;
    account_migrate(&exe, &address, &password)?;

    StorageDirs::clear_cache_dir();
    std::env::remove_var("SOS_CACHE");
    std::env::remove_var("SOS_YES");
    std::env::remove_var("SOS_PASSWORD");
    Ok(())
}

/// Create a new account.
fn account_new(exe: &str, password: &SecretString) -> Result<()> {
    let cmd = format!("{} account new {}", exe, ACCOUNT_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("2[)] Choose a password")?;
        p.send_line("2")?;
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
        p.exp_regex("Confirm password:")?;
        p.send_line(password.expose_secret())?;
        p.exp_regex("you want to create a new account")?;
        p.send_line("y")?;
    }
    p.exp_eof()?;

    Ok(())
}

/// List accounts.
fn account_list(exe: &str) -> Result<String> {
    let cmd = format!("{} account ls", exe);
    let mut p = spawn(&cmd, TIMEOUT)?;
    p.exp_string(ACCOUNT_NAME)?;
    p.exp_eof()?;

    let cmd = format!("{} account ls -v", exe);
    let mut p = spawn(&cmd, TIMEOUT)?;
    let result = p.read_line()?;
    p.exp_eof()?;

    let mut parts: Vec<&str> = result.split(' ').collect();
    let address: &str = parts.remove(0);
    let name: &str = parts.remove(0);

    assert!(address.parse::<Address>().is_ok());
    assert_eq!(ACCOUNT_NAME, name);
    Ok(address.to_owned())
}

fn account_backup_restore(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cache_dir = StorageDirs::cache_dir().unwrap();
    let backup_file = cache_dir.join(format!("{}-backup.zip", address));

    let cmd = format!(
        "{} account backup -o {}",
        exe,
        backup_file.to_string_lossy()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    p.exp_regex("backup archive created")?;
    p.exp_eof()?;

    let cmd = format!(
        "{} account restore -i {}",
        exe,
        backup_file.to_string_lossy()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Overwrite all account")?;
        p.send_line("y")?;
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex(&format!("restored {}", ACCOUNT_NAME))?;
    p.exp_eof()?;

    Ok(())
}

fn account_info(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!("{} account info -a {}", exe, address);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} account info -a {} -v", exe, address);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} account info -a {} --json", exe, address);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn account_rename(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd =
        format!("{} account rename -a {} --name {}", exe, address, NEW_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("account renamed")?;
    p.exp_eof()?;

    let cmd = format!(
        "{} account rename -a {} --name {}",
        exe, address, ACCOUNT_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("account renamed")?;
    p.exp_eof()?;

    Ok(())
}

fn account_migrate(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cache_dir = StorageDirs::cache_dir().unwrap();
    let export_file = cache_dir.join(format!("{}-export.zip", address));
    let fixtures = PathBuf::from("workspace/migrate/fixtures");

    let cmd = format!(
        "{} account migrate -a {} export {}",
        exe,
        address,
        export_file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
        p.exp_regex("Export UNENCRYPTED account")?;
        p.send_line("y")?;
    }
    p.exp_regex("account exported")?;
    p.exp_eof()?;

    let cmd = format!(
        "{} account migrate -a {} export --force {}",
        exe,
        address,
        export_file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
        p.exp_regex("Export UNENCRYPTED account")?;
        p.send_line("y")?;
    }
    p.exp_regex("account exported")?;
    p.exp_eof()?;

    let file = fixtures.join("1password-export.csv");
    let cmd = format!(
        "{} account migrate -a {} import --format {} {}",
        exe,
        address,
        ImportFormat::OnePasswordCsv.to_string(),
        file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("file imported")?;
    p.exp_eof()?;

    let file = fixtures.join("dashlane-export.zip");
    let cmd = format!(
        "{} account migrate -a {} import --format {} {}",
        exe,
        address,
        ImportFormat::DashlaneZip.to_string(),
        file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("file imported")?;
    p.exp_eof()?;

    let file = fixtures.join("bitwarden-export.csv");
    let cmd = format!(
        "{} account migrate -a {} import --format {} {}",
        exe,
        address,
        ImportFormat::BitwardenCsv.to_string(),
        file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("file imported")?;
    p.exp_eof()?;

    let file = fixtures.join("chrome-export.csv");
    let cmd = format!(
        "{} account migrate -a {} import --format {} {}",
        exe,
        address,
        ImportFormat::ChromeCsv.to_string(),
        file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("file imported")?;
    p.exp_eof()?;

    let file = fixtures.join("firefox-export.csv");
    let cmd = format!(
        "{} account migrate -a {} import --format {} {}",
        exe,
        address,
        ImportFormat::FirefoxCsv.to_string(),
        file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("file imported")?;
    p.exp_eof()?;

    let file = fixtures.join("macos-export.csv");
    let cmd = format!(
        "{} account migrate -a {} import --format {} {}",
        exe,
        address,
        ImportFormat::MacosCsv.to_string(),
        file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("file imported")?;
    p.exp_eof()?;

    Ok(())
}
