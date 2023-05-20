use super::*;
use anyhow::Result;
use rexpect::spawn;
use secrecy::SecretString;
use sos_sdk::{
    constants::DEFAULT_VAULT_NAME, secrecy::ExposeSecret,
    signer::ecdsa::Address, vault::VaultId,
};

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

pub fn set_note_ci_vars() {
    std::env::set_var("SOS_NOTE", NOTE_VALUE.to_string());
}

pub fn clear_note_ci_vars() {
    std::env::remove_var("SOS_NOTE");
}

pub fn set_login_ci_vars(account_password: &SecretString) {
    std::env::set_var("SOS_LOGIN_USERNAME", LOGIN_SERVICE_NAME.to_string());
    std::env::set_var("SOS_LOGIN_URL", LOGIN_URL.to_string());
    std::env::set_var(
        "SOS_LOGIN_PASSWORD",
        account_password.expose_secret().to_string(),
    );
}

pub fn clear_login_ci_vars() {
    std::env::remove_var("SOS_LOGIN_USERNAME");
    std::env::remove_var("SOS_LOGIN_URL");
    std::env::remove_var("SOS_LOGIN_PASSWORD");
}

pub fn set_list_ci_vars(value_1: &SecretString, value_2: &SecretString) {
    std::env::set_var(
        "SOS_LIST",
        format!(
            "{}={}\n{}={}\n",
            LIST_KEY_1,
            value_1.expose_secret(),
            LIST_KEY_2,
            value_2.expose_secret()
        ),
    );
}

pub fn clear_list_ci_vars() {
    std::env::remove_var("SOS_LIST");
}

pub fn set_link_ci_vars() {
    std::env::set_var("SOS_LINK", LINK_VALUE.to_string());
}

pub fn clear_link_ci_vars() {
    std::env::remove_var("SOS_LINK");
}

pub fn set_password_ci_vars(attachment_password: &SecretString) {
    std::env::set_var(
        "SOS_PASSWORD_VALUE",
        attachment_password.expose_secret().to_string(),
    );
}

pub fn clear_password_ci_vars() {
    std::env::remove_var("SOS_PASSWORD_VALUE");
}
