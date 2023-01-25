//! Import from keychain access.
pub mod error;
pub mod parser;

pub use error::Error;

/// Result type for keychain access integration.
pub type Result<T> = std::result::Result<T, Error>;

use sos_core::{
    crypto::secret_key::Seed,
    secret::{Secret, SecretMeta},
    vault::Vault,
    Gatekeeper,
};

use std::{
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::{channel, Receiver},
};

use parser::{AttributeName, KeychainList, KeychainParser};
use secrecy::{ExposeSecret, SecretString};

use security_framework::os::macos::keychain::SecKeychain;

use crate::Convert;

/// File extension for keychain files.
const KEYCHAIN_DB: &str = "keychain-db";

/// Import keychains.
pub struct KeychainImport;

impl KeychainImport {
    /// Attempt to generate a dump containing the secret data.
    ///
    /// Requires an existing dump without the data so we can
    /// verify the password prior to attempting to autofill all secrets.
    ///
    /// If a password is given then we verify it by trying to
    /// decrypt the first entry.
    ///
    /// If verification is correct then we proceed to autofill all fields.
    ///
    /// If no password is given then the user must enter the password for
    /// each secret.
    pub fn import_data<'a>(
        keychain: &UserKeychain,
        dump: &'a str,
        password: Option<SecretString>,
    ) -> Result<Option<String>> {
        let parser = KeychainParser::new(dump);
        let list = parser.parse()?;
        if !list.is_empty() {
            if let (Some(password), Some((service, account, _))) =
                (password, list.first_generic_password())
            {
                Self::verify_autofill_password(
                    keychain,
                    service,
                    account,
                    password.expose_secret(),
                )?;
                // Now do a dump and include all the data using
                // the autofill script to enter the password for every entry
                let data = Self::dump_data_autofill(
                    keychain,
                    password.expose_secret(),
                )?;
                return Ok(Some(data));
            } else {
                // User must manually enter the passphrase for each secret
                let data = dump_keychain(&keychain.path, true)?;
                return Ok(Some(data));
            }
        }
        Ok(None)
    }

    fn dump_data_autofill(
        keychain: &UserKeychain,
        password: &str,
    ) -> Result<String> {
        let (tx, rx) = channel::<bool>();
        spawn_password_autofill_osascript(rx, password);
        let output = dump_keychain(&keychain.path, true)?;
        tx.send(true)?;
        Ok(output)
    }

    fn verify_autofill_password(
        keychain: &UserKeychain,
        service: &str,
        account: &str,
        password: &str,
    ) -> Result<()> {
        // TODO: handle timeout if wrong password
        let (tx, rx) = channel::<bool>();
        spawn_password_autofill_osascript(rx, password);
        let keychain = SecKeychain::open(&keychain.path)?;
        let (_, _) = keychain.find_generic_password(service, account)?;
        tx.send(true)?;
        Ok(())
    }
}

impl Convert for KeychainImport {
    type Input = String;

    fn convert(
        source: Self::Input,
        password: SecretString,
        seed: Option<Seed>,
    ) -> crate::Result<Vault> {
        let mut vault: Vault = Default::default();
        vault.initialize(password.expose_secret(), seed)?;

        let parser = KeychainParser::new(&source);
        let list = parser.parse()?;

        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(password.expose_secret())?;

        for entry in list.entries() {
            /// Must have some data for the secret
            if let (Some((_, attr_service)), Some(data)) = (
                entry.find_attribute_by_name(
                    AttributeName::SecServiceItemAttr,
                ),
                entry.data(),
            ) {
                if let Some(generic_data) = entry.generic_data()? {
                    if entry.is_note() {
                        let text = generic_data.into_owned();
                        let secret = Secret::Note {
                            text: SecretString::new(text),
                            user_data: Default::default(),
                        };

                        let meta = SecretMeta::new(
                            attr_service.as_str().to_owned(),
                            secret.kind(),
                        );

                        keeper.create(meta, secret)?;
                    } else {
                        if let Some((_, attr_account)) = entry
                            .find_attribute_by_name(
                                AttributeName::SecAccountItemAttr,
                            )
                        {
                            let password = generic_data.into_owned();
                            let secret = Secret::Account {
                                account: attr_account.as_str().to_owned(),
                                password: SecretString::new(password),
                                url: None,
                                user_data: Default::default(),
                            };

                            let meta = SecretMeta::new(
                                attr_service.as_str().to_owned(),
                                secret.kind(),
                            );

                            keeper.create(meta, secret)?;
                        }
                    }
                }
            }
        }

        Ok(keeper.take())
    }
}

/// Get the stdout of a keychain dump by calling
/// the `security dump-keychain` command.
///
/// If the `data` flag is given a password prompt will
/// be shown for every entry.
pub fn dump_keychain<P: AsRef<Path>>(path: P, data: bool) -> Result<String> {
    let mut args = vec!["dump-keychain"];
    if data {
        args.push("-d");
    }
    let path = path.as_ref().to_string_lossy();
    args.push(path.as_ref());
    let dump = Command::new("security").args(args).output()?;
    let result = std::str::from_utf8(&dump.stdout)?.to_owned();
    Ok(result)
}

/// Located keychain with full path and name derived from the
/// file stem.
pub struct UserKeychain {
    /// Name of the keychain.
    name: String,
    /// Path to the keychain.
    path: PathBuf,
}

/// Attempt to find keychains by searching the standard
/// user directory (`~/Library/Keychains`).
pub fn user_keychains() -> Result<Vec<UserKeychain>> {
    let mut keychains = Vec::new();
    let home = dirs::home_dir().unwrap();
    let path = home.join("Library/Keychains");

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(extension) = path.extension() {
            if extension == KEYCHAIN_DB {
                let name = path
                    .file_stem()
                    .ok_or(Error::NoKeychainName)?
                    .to_string_lossy();
                keychains.push(UserKeychain {
                    name: name.into_owned(),
                    path: path.to_path_buf(),
                });
            }
        }
    }
    Ok(keychains)
}

/// Attempt to autofill the security agent password prompts
/// with the given password using some Applescript.
///
/// Requires that the Accessibility permission has been given
/// to the application in System Preferences.
pub fn spawn_password_autofill_osascript(rx: Receiver<bool>, password: &str) {
    let script = format!(
        r#"
-- Autofill the passwords
set thePassword to "{}"
delay 0.5
tell application "System Events"
repeat while exists (processes where name is "SecurityAgent")
    tell process "SecurityAgent"
        set frontmost to true
        try
            --if exists (text field 1 of window 1) then
            --    set value of text field 1 of window 1 to thePassword
            --    keystroke return
            --end if

            keystroke thePassword
            delay 0.1
            keystroke return
            delay 0.1
        on error
                exit
        end try
    end tell
    delay 0.5
end repeat
end tell
"#,
        password
    );

    std::thread::spawn(move || {
        let mut child = Command::new("osascript")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let mut writer = BufWriter::new(&mut stdin);
        writer
            .write_all(script.as_bytes())
            .expect("failed to write to child script");

        // Got a signal to kill the process, we need to do this
        // otherwise the applescript keeps running while the SecurityAgent
        // process is closing and keeps trying to steal focus
        std::thread::spawn(move || {
            if rx.recv().is_ok() {
                let _ = child.kill();
            }
        });
    });
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;
    use sos_core::secret::SecretId;

    fn find_test_keychain() -> Result<UserKeychain> {
        // NOTE: the keychain must be located in ~/Library/Keychains
        // NOTE: otherwise searching fails to find any items
        // NOTE: and the `security` program does not work
        let keychains = user_keychains()?;
        let keychain = keychains.into_iter().find(|k| k.name == "sos-mock");
        if keychain.is_none() {
            eprintln!("To test the MacOS keychain export you must have a keychain called `sos-mock` in ~/Library/Keychains.");
            panic!("keychain test for MacOS not configured");
        }
        Ok(keychain.unwrap())
    }

    #[test]
    fn keychain_dump() -> Result<()> {
        let keychain = find_test_keychain()?;
        let source = dump_keychain(keychain.path, false)?;
        assert!(!source.is_empty());
        Ok(())
    }

    #[test]
    #[cfg(feature = "interactive-keychain-tests")]
    fn keychain_import_autofill() -> Result<()> {
        let keychain = find_test_keychain()?;
        let source = dump_keychain(&keychain.path, false)?;
        let password = SecretString::new("mock-password".to_owned());
        let data_dump =
            KeychainImport::import_data(&keychain, &source, Some(password))?;
        assert!(data_dump.is_some());

        let vault_password =
            SecretString::new("mock-vault-password".to_owned());
        let vault = KeychainImport::convert(
            data_dump.unwrap(),
            vault_password.clone(),
            None,
        )?;

        assert_eq!(2, vault.len());

        // Assert on the data
        let keys: Vec<SecretId> = vault.keys().copied().collect();
        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(vault_password.expose_secret())?;

        for key in &keys {
            if let Some((meta, secret, _)) = keeper.read(key)? {
                match secret {
                    Secret::Note { text, .. } => {
                        assert_eq!(
                            "mock-secure-note-value",
                            text.expose_secret()
                        );
                    }
                    Secret::Account {
                        account, password, ..
                    } => {
                        assert_eq!("test account", account);
                        assert_eq!(
                            "mock-password-value",
                            password.expose_secret()
                        );
                    }
                    _ => unreachable!(),
                }
            } else {
                panic!("expecting entry in the vault");
            }
        }

        Ok(())
    }
}
