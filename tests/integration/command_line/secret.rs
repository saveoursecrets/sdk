use anyhow::Result;
use serial_test::serial;
use std::{
    ops::DerefMut,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

use sos_sdk::{
    constants::DEFAULT_VAULT_NAME, passwd::diceware::generate_passphrase,
    secrecy::ExposeSecret, signer::ecdsa::Address, storage::StorageDirs,
    vault::VaultId,
};

use sos_net::migrate::import::ImportFormat;

use secrecy::SecretString;

use rexpect::{reader::Regex, session::PtySession, spawn, ReadUntil};

use super::*;

pub fn add_note(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    if is_ci() {
        std::env::set_var("SOS_NOTE", NOTE_VALUE.to_string());
    }

    let cmd =
        format!("{} secret add note -a {} -n {}", exe, address, NOTE_NAME);

    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex(">> ")?;
        p.send_line(NOTE_VALUE)?;
        p.exp_regex(">> ")?;
        p.send_control('d')?;
    }

    p.exp_regex("Secret created")?;
    p.exp_eof()?;

    if is_ci() {
        std::env::remove_var("SOS_NOTE");
    }

    Ok(())
}

pub fn add_file(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let file = PathBuf::from("tests/fixtures/sample.heic").canonicalize()?;
    let cmd = format!(
        "{} secret add file -a {} -n {} {}",
        exe,
        address,
        FILE_NAME,
        file.display()
    );

    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }

    p.exp_regex("Secret created")?;
    p.exp_eof()?;

    Ok(())
}

pub fn add_login(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let (account_password, _) = generate_passphrase()?;

    if is_ci() {
        std::env::set_var(
            "SOS_LOGIN_USERNAME",
            LOGIN_SERVICE_NAME.to_string(),
        );
        std::env::set_var("SOS_LOGIN_URL", LOGIN_URL.to_string());
        std::env::set_var(
            "SOS_LOGIN_PASSWORD",
            account_password.expose_secret().to_string(),
        );
    }

    let cmd =
        format!("{} secret add login -a {} -n {}", exe, address, LOGIN_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex("Username:")?;
        p.send_line(LOGIN_SERVICE_NAME)?;

        p.exp_regex("Website:")?;
        p.send_line(LOGIN_URL)?;

        p.exp_regex("Password:")?;
        p.send_line(account_password.expose_secret())?;
    }

    p.exp_regex("Secret created")?;
    p.exp_eof()?;

    if is_ci() {
        std::env::remove_var("SOS_LOGIN_USERNAME");
        std::env::remove_var("SOS_LOGIN_URL");
        std::env::remove_var("SOS_LOGIN_PASSWORD");
    }

    Ok(())
}

pub fn add_list(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let (value_1, _) = generate_passphrase()?;
    let (value_2, _) = generate_passphrase()?;

    if is_ci() {
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

    let cmd =
        format!("{} secret add list -a {} -n {}", exe, address, LIST_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex("Key:")?;
        p.send_line(LIST_KEY_1)?;

        p.exp_regex("Value:")?;
        p.send_line(value_1.expose_secret())?;

        p.exp_regex("Add more")?;
        p.send_line("y")?;

        p.exp_regex("Key:")?;
        p.send_line(LIST_KEY_2)?;

        p.exp_regex("Value:")?;
        p.send_line(value_2.expose_secret())?;

        p.exp_regex("Add more")?;
        p.send_line("n")?;
    }

    p.exp_regex("Secret created")?;
    p.exp_eof()?;

    if is_ci() {
        std::env::remove_var("SOS_LIST");
    }

    Ok(())
}

pub fn list(exe: &str, address: &str, password: &SecretString) -> Result<()> {
    let cmd = format!("{} secret list -a {}", exe, address);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} secret list --verbose -a {}", exe, address);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} secret list --all -a {}", exe, address);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} secret list --favorites -a {}", exe, address);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

pub fn get(exe: &str, address: &str, password: &SecretString) -> Result<()> {
    let cmd = format!("{} secret get -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} secret get -a {} {}", exe, address, FILE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} secret get -a {} {}", exe, address, LOGIN_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} secret get -a {} {}", exe, address, LIST_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

pub fn info(exe: &str, address: &str, password: &SecretString) -> Result<()> {
    let cmd = format!("{} secret info -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd =
        format!("{} secret info --debug -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd =
        format!("{} secret info --json -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

pub fn tags(exe: &str, address: &str, password: &SecretString) -> Result<()> {
    let tags = "foo,bar,qux";

    let cmd = format!(
        "{} secret tags add -a {} --tags {} {}",
        exe, address, tags, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd =
        format!("{} secret tags list -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!(
        "{} secret tags rm -a {} --tags {} {}",
        exe, address, "foo,bar", NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd =
        format!("{} secret tags clear -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

pub fn favorite(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    // Add to favorites with first toggle
    let cmd = format!("{} secret favorite -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    // Remove from favorites with second toggle
    let cmd = format!("{} secret favorite -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

pub fn rename(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!(
        "{} secret rename -a {} --name {} {}",
        exe, address, NEW_NOTE_NAME, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!(
        "{} secret rename -a {} --name {} {}",
        exe, address, NOTE_NAME, NEW_NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

pub fn mv(exe: &str, address: &str, password: &SecretString) -> Result<()> {
    let target_folder = "moved-secret-folder";

    // Create temporary folder
    let cmd = format!("{} folder new -a {} {}", exe, address, target_folder);

    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Folder created")?;
    p.exp_eof()?;

    // Move to the new folder
    let cmd = format!(
        "{} secret move -a {} --target {} {}",
        exe, address, target_folder, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Secret moved")?;
    p.exp_eof()?;

    // Move back to the default folder
    let cmd = format!(
        "{} secret move -a {} --target {} --folder {} {}",
        exe, address, DEFAULT_VAULT_NAME, target_folder, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Secret moved")?;
    p.exp_eof()?;

    // Clean up the temporary folder
    let cmd =
        format!("{} folder remove -a {} {}", exe, address, target_folder);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex("Delete folder")?;
        p.send_line("y")?;
    }
    p.exp_regex("Folder deleted")?;
    p.exp_eof()?;

    Ok(())
}

pub fn comment(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    // Set a comment
    let cmd = format!(
        "{} secret comment -a {} --text {} {}",
        exe, address, "mock-comment", NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    // Clear the comment
    let cmd = format!(
        "{} secret comment -a {} --text '' {}",
        exe, address, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

pub fn archive_unarchive(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    // Move to archive
    let cmd = format!("{} secret archive -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Moved to archive")?;
    p.exp_eof()?;

    // Restore from archive
    let cmd =
        format!("{} secret unarchive -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Restored from archive")?;
    p.exp_eof()?;

    Ok(())
}

pub fn download(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cache_dir = StorageDirs::cache_dir().unwrap();
    let output = cache_dir.join("sample.heic");

    let cmd = format!(
        "{} secret download -a {} {} {}",
        exe,
        address,
        FILE_NAME,
        output.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Download complete")?;
    p.exp_eof()?;

    assert!(output.exists());

    Ok(())
}

pub fn attach(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cache_dir = StorageDirs::cache_dir().unwrap();
    let input = PathBuf::from("tests/fixtures/sample.heic").canonicalize()?;
    let output = cache_dir.join("sample-attachment.heic");

    // Create file attachment
    let cmd = format!(
        "{} secret attach add file -a {} --name {} --path {} {}",
        exe,
        address,
        FILE_ATTACHMENT,
        input.display(),
        NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Secret updated")?;
    p.exp_eof()?;

    // Create note attachment
    if is_ci() {
        std::env::set_var("SOS_NOTE", NOTE_VALUE.to_string());
    }
    let cmd = format!(
        "{} secret attach add note -a {} --name {} {}",
        exe, address, NOTE_ATTACHMENT, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex(">> ")?;
        p.send_line(NOTE_VALUE)?;
        p.exp_regex(">> ")?;
        p.send_control('d')?;
    }
    p.exp_regex("Secret updated")?;
    p.exp_eof()?;
    if is_ci() {
        std::env::remove_var("SOS_NOTE");
    }

    // Create link attachment
    if is_ci() {
        std::env::set_var("SOS_LINK", LINK_VALUE.to_string());
    }
    let cmd = format!(
        "{} secret attach add link -a {} --name {} {}",
        exe, address, LINK_ATTACHMENT, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex("URL:")?;
        p.send_line(LINK_VALUE)?;
    }
    p.exp_regex("Secret updated")?;
    p.exp_eof()?;
    if is_ci() {
        std::env::remove_var("SOS_LINK");
    }

    // Create password attachment
    let (attachment_password, _) = generate_passphrase()?;
    if is_ci() {
        std::env::set_var(
            "SOS_PASSWORD_VALUE",
            attachment_password.expose_secret().to_string(),
        );
    }
    let cmd = format!(
        "{} secret attach add password -a {} --name {} {}",
        exe, address, PASSWORD_ATTACHMENT, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex("Password:")?;
        p.send_line(attachment_password.expose_secret())?;
    }
    p.exp_regex("Secret updated")?;
    p.exp_eof()?;
    if is_ci() {
        std::env::remove_var("SOS_PASSWORD_VALUE");
    }

    // Get an attachment
    let cmd = format!(
        "{} secret attach get -a {} {} {}",
        exe, address, NOTE_NAME, NOTE_ATTACHMENT,
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    // List attachments
    let cmd =
        format!("{} secret attach ls -a {} {}", exe, address, NOTE_NAME,);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!(
        "{} secret attach ls --verbose -a {} {}",
        exe, address, NOTE_NAME,
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    // Download file attachment
    let cmd = format!(
        "{} secret attach download -a {} {} {} {}",
        exe,
        address,
        NOTE_NAME,
        FILE_ATTACHMENT,
        output.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Download complete")?;
    p.exp_eof()?;
    assert!(output.exists());

    // Remove an attachment
    let cmd = format!(
        "{} secret attach remove -a {} {} {}",
        exe, address, NOTE_NAME, NOTE_ATTACHMENT,
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

pub fn remove(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!("{} secret remove -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
        p.exp_regex("Delete secret")?;
        p.send_line("y")?;
    }
    p.exp_regex("Secret deleted")?;
    p.exp_eof()?;

    Ok(())
}
