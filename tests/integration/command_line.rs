use anyhow::Result;
use serial_test::serial;
use std::path::PathBuf;

use sos_core::{
    signer::ecdsa::Address,
    passwd::diceware::generate_passphrase, secrecy::ExposeSecret,
};

use rexpect::spawn;

#[tokio::test]
#[serial]
async fn integration_command_line() -> Result<()> {
    let account_name = "mock-account";
    let (password, _) = generate_passphrase()?;

    let cache_dir = PathBuf::from("target/command_line_test");
    if cache_dir.exists() {
        std::fs::remove_dir_all(&cache_dir)?;
    }
    std::fs::create_dir_all(&cache_dir)?;

    let cache_dir = cache_dir.canonicalize()?;
    std::env::set_var("SOS_CACHE", cache_dir.clone());

    let is_coverage = std::env::var("COVERAGE_BINARIES").is_ok();
    let exe = if is_coverage {
        PathBuf::from(std::env::var("COVERAGE_BINARIES")?)
            .join("sos")
            .to_string_lossy()
            .into_owned()
    } else {
        "target/debug/sos".to_owned()
    };
    let cmd = format!("{} account new {}", exe, account_name);
    let mut p = spawn(&cmd, None)?;
    p.exp_regex("2[)] Choose a password")?;
    p.send_line("2")?;
    p.exp_regex("Password:")?;
    p.send_line(password.expose_secret())?;
    p.exp_regex("Confirm password:")?;
    p.send_line(password.expose_secret())?;
    p.exp_regex("you want to create a new account")?;
    p.send_line("y")?;
    p.exp_eof()?;
    
    let cmd = format!("{} account ls", exe);
    let mut p = spawn(&cmd, None)?;
    p.exp_string(account_name)?;
    p.exp_eof()?;

    let cmd = format!("{} account ls -v", exe);
    let mut p = spawn(&cmd, None)?;
    let result = p.read_line()?;
    p.exp_eof()?;

    let mut parts: Vec<&str> = result.split(' ').collect();
    let address: &str = parts.remove(0);
    let name: &str = parts.remove(0);

    assert!(address.parse::<Address>().is_ok());
    assert_eq!(account_name, name);

    let backup_file = cache_dir.join(format!("{}-backup.zip", &address));

    let cmd = format!("{} account backup -o {}",
        exe, backup_file.to_string_lossy());
    let mut p = spawn(&cmd, None)?;
    p.exp_regex("backup archive created")?;
    p.exp_eof()?;

    let cmd = format!("{} account restore -i {}",
        exe, backup_file.to_string_lossy());
    let mut p = spawn(&cmd, None)?;
    p.exp_regex("Overwrite all account")?;
    p.send_line("y")?;
    p.exp_regex("Password:")?;
    p.send_line(password.expose_secret())?;
    p.exp_regex(&format!("restored {}", account_name))?;
    p.exp_eof()?;
    
    std::env::remove_var("SOS_CACHE");
    Ok(())
}
