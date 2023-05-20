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

/// Create a new account.
pub fn new(exe: &str, password: &SecretString, name: &str) -> Result<()> {
    let cmd = format!("{} account new {}", exe, name);
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
pub fn list(
    exe: &str,
    name: &str,
    launch: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!("{} account ls", exe);
    run!(launch, cmd, true, |ps: &mut PtySession,
                             prompt: Option<&str>|
     -> Result<()> {
        ps.exp_string(name)?;
        Ok(())
    });

    let cmd = format!("{} account ls -v", exe);
    run!(launch, cmd, true, |ps: &mut PtySession,
                             prompt: Option<&str>|
     -> Result<()> {
        ps.exp_regex(name)?;
        Ok(())
    });

    Ok(())
}

pub fn backup_restore(
    exe: &str,
    address: &str,
    password: &SecretString,
    account_name: &str,
    launch: Option<(Session, &str)>,
) -> Result<()> {
    let cache_dir = StorageDirs::cache_dir().unwrap();
    let backup_file = cache_dir.join(format!("{}-backup.zip", address));

    let cmd = format!(
        "{} account backup -a {} -o {}",
        exe,
        address,
        backup_file.to_string_lossy()
    );
    run!(launch, cmd, true, |ps: &mut PtySession,
                             prompt: Option<&str>|
     -> Result<()> {
        ps.exp_regex("backup archive created")?;
        Ok(())
    });

    let cmd = format!(
        "{} account restore -i {}",
        exe,
        backup_file.to_string_lossy()
    );
    run!(launch, cmd, true, |ps: &mut PtySession,
                             prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() {
            ps.exp_regex("Overwrite all account")?;
            ps.send_line("y")?;
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }

        ps.exp_regex(&format!("restored {}", account_name))?;
        Ok(())
    });

    Ok(())
}

pub fn info(
    exe: &str,
    address: &str,
    password: &SecretString,
    launch: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!("{} account info -a {}", exe, address);
    run!(launch, cmd, true, |ps: &mut PtySession,
                             prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        Ok(())
    });

    let cmd = format!("{} account info -a {} -v", exe, address);
    run!(launch, cmd, true, |ps: &mut PtySession,
                             prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        Ok(())
    });

    let cmd = format!("{} account info -a {} --json", exe, address);
    run!(launch, cmd, true, |ps: &mut PtySession,
                             prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        Ok(())
    });

    Ok(())
}

pub fn rename(
    exe: &str,
    address: &str,
    password: &SecretString,
    account_name: &str,
    launch: Option<(Session, &str)>,
) -> Result<()> {
    // Must update expected prompt
    let new_prompt = format_prompt(NEW_ACCOUNT_NAME, DEFAULT_VAULT_NAME);
    let renamed = launch.clone().map(|(s, p)| (s, &new_prompt[..]));

    // Rename account
    let cmd = format!(
        "{} account rename -a {} --name {}",
        exe, address, NEW_ACCOUNT_NAME
    );
    run!(renamed, cmd, true, |ps: &mut PtySession,
                              prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        ps.exp_regex("account renamed")?;
        Ok(())
    });

    // Rename again to revert
    let cmd = format!(
        "{} account rename -a {} --name {}",
        exe, address, account_name
    );

    run!(launch, cmd, true, |ps: &mut PtySession,
                             prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        ps.exp_regex("account renamed")?;
        Ok(())
    });

    Ok(())
}

pub fn migrate(
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
        ImportFormat::OnePasswordCsv,
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
        ImportFormat::DashlaneZip,
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
        ImportFormat::BitwardenCsv,
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
        ImportFormat::ChromeCsv,
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
        ImportFormat::FirefoxCsv,
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
        ImportFormat::MacosCsv,
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

pub fn contacts(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let import_file = PathBuf::from("tests/fixtures/contacts.vcf");

    let cache_dir = StorageDirs::cache_dir().unwrap();
    let export_file = cache_dir.join(format!("{}-contacts.vcf", address));

    let cmd = format!(
        "{} account contacts -a {} import {}",
        exe,
        address,
        import_file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("contacts imported")?;
    p.exp_eof()?;

    let cmd = format!(
        "{} account contacts -a {} export {}",
        exe,
        address,
        export_file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("contacts exported")?;
    p.exp_eof()?;

    Ok(())
}

pub fn delete(
    exe: &str,
    address: &str,
    password: &SecretString,
    launch: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = if launch.is_some() {
        format!("{} account delete", exe)
    } else {
        format!("{} account delete -a {}", exe, address)
    };
    run!(launch, cmd, false, |ps: &mut PtySession,
                              prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
            ps.exp_regex("Delete account")?;
            ps.send_line("y")?;
        }

        ps.exp_regex("account deleted")?;
        // Delete the account kills the process
        // so now we expect EOF for the shell and
        // normal execution
        ps.exp_eof()?;
        Ok(())
    });
    Ok(())
}
