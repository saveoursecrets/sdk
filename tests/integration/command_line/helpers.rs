use anyhow::Result;
use sos_sdk::{
    constants::DEFAULT_VAULT_NAME, secrecy::ExposeSecret,
    signer::ecdsa::Address, vault::VaultId,
};
use secrecy::SecretString;
use rexpect::spawn;
use super::*;

/// Get the id of the default folder so we can
/// use it to execute the check subcommand which requires
/// paths to the files to check.
pub fn default_folder_id(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<VaultId> {
    let cmd =
        format!("{} folder info -a {} {}", exe, address, DEFAULT_VAULT_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
        p.read_line()?;
    }

    let result = p.read_line()?;
    p.exp_eof()?;

    Ok(result.parse()?)
}

/// Parse the address from the first account in the accounts list.
pub fn first_account_address(exe: &str, name: &str) -> Result<String> {
    let cmd = format!("{} account ls -v", exe);
    let mut p = spawn(&cmd, TIMEOUT)?;
    let result = p.read_line()?;
    p.exp_eof()?;

    let mut parts: Vec<&str> = result.split(' ').collect();
    let address: &str = parts.remove(0);
    let account_name: &str = parts.remove(0);

    assert!(address.parse::<Address>().is_ok());
    assert_eq!(name, account_name);
    Ok(address.to_owned())
}
