use anyhow::Result;
use serial_test::serial;
use std::path::PathBuf;

use sos_core::{
    passwd::diceware::generate_passphrase, secrecy::ExposeSecret,
    signer::ecdsa::Address,
    storage::StorageDirs,
};

use secrecy::SecretString;

use rexpect::spawn;

const ACCOUNT_NAME: &str = "mock-account";
const TIMEOUT: Option<u64> = Some(30000);

fn is_coverage() -> bool {
    std::env::var("COVERAGE_BINARIES").is_ok()
}

fn is_ci() -> bool {
    std::env::var("CI").is_ok()
}

#[tokio::test]
#[serial]
async fn command_line() -> Result<()> {
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
        std::env::set_var("SOS_PASSWORD", password.expose_secret().to_owned());
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
