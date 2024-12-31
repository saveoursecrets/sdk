//! Import from keychain access and passwords CSV.
use async_trait::async_trait;
pub use error::Error;

pub mod error;

/// Result type for keychain access integration.
pub type Result<T> = std::result::Result<T, Error>;

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::{channel, Receiver},
};

use sos_sdk::{
    crypto::AccessKey,
    search::SearchIndex,
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow},
        Gatekeeper, Vault,
    },
};

use keychain_parser::{AttributeName, KeychainParser};
use secrecy::{ExposeSecret, SecretString};
use security_framework::{
    item::{ItemClass, ItemSearchOptions},
    os::macos::{item::ItemSearchOptionsExt, keychain::SecKeychain},
};

use crate::Convert;

/// Import a MacOS keychain access dump into a vault.
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
    pub fn import_data(
        keychain: &UserKeychain,
        password: Option<SecretString>,
    ) -> Result<Option<String>> {
        if let Some(password) = password {
            if Self::verify_autofill_password(
                keychain,
                password.expose_secret(),
            )? {
                // Now do a dump and include all the data using
                // the autofill script to enter the password for every entry
                let data = Self::dump_data_autofill(
                    keychain,
                    password.expose_secret(),
                )?;
                Ok(Some(data))
            } else {
                Ok(None)
            }
        } else {
            // User must manually enter the passphrase for each secret
            let data = dump_keychain(&keychain.path, true)?;
            Ok(Some(data))
        }
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
        password: &str,
    ) -> Result<bool> {
        let keychain = SecKeychain::open(&keychain.path)?;
        let mut searcher = ItemSearchOptions::new();
        searcher.class(ItemClass::generic_password());
        searcher.load_attributes(true);
        searcher.load_data(true);
        searcher.keychains(&[keychain]);
        searcher.limit(1);

        // TODO: handle timeout if wrong password
        let (tx, rx) = channel::<bool>();
        spawn_password_autofill_osascript(rx, password);
        match searcher.search() {
            Ok(_) => {
                tx.send(true)?;
                Ok(true)
            }
            Err(_) => {
                tx.send(true)?;
                Ok(false)
            }
        }
    }
}

async fn rename_label(
    keeper: &mut Gatekeeper,
    label: String,
    duplicates: &mut HashMap<String, usize>,
    index: &SearchIndex,
) -> String {
    if index
        .find_by_label(keeper.vault().id(), &label, None)
        .is_some()
    {
        duplicates
            .entry(label.clone())
            .and_modify(|counter| *counter += 1)
            .or_insert(1);
        let counter = duplicates.get(&label).unwrap();
        format!("{} {}", label, counter)
    } else {
        label
    }
}

#[async_trait]
impl Convert for KeychainImport {
    type Input = String;

    async fn convert(
        &self,
        source: Self::Input,
        vault: Vault,
        key: &AccessKey,
    ) -> crate::Result<Vault> {
        let parser = KeychainParser::new(&source);
        let list = parser.parse()?;

        let mut index = SearchIndex::new();
        let mut keeper = Gatekeeper::new(vault);
        keeper.unlock(&key).await?;

        let mut duplicates: HashMap<String, usize> = HashMap::new();

        for entry in list.entries() {
            // Must have some data for the secret
            if let (Some((_, attr_service)), Some(_)) = (
                entry.find_attribute_by_name(
                    AttributeName::SecServiceItemAttr,
                ),
                entry.data(),
            ) {
                if let Some(generic_data) = entry.generic_data()? {
                    let label = attr_service.as_str().to_owned();
                    let label = rename_label(
                        &mut keeper,
                        label,
                        &mut duplicates,
                        &index,
                    )
                    .await;
                    if entry.is_note() {
                        let text = generic_data.into_owned();
                        let secret = Secret::Note {
                            text: text.into(),
                            user_data: Default::default(),
                        };

                        let meta = SecretMeta::new(label, secret.kind());
                        let secret_data =
                            SecretRow::new(SecretId::new_v4(), meta, secret);
                        keeper.create_secret(&secret_data).await?;
                    } else if let Some((_, attr_account)) = entry
                        .find_attribute_by_name(
                            AttributeName::SecAccountItemAttr,
                        )
                    {
                        let password = generic_data.into_owned();
                        let secret = Secret::Account {
                            account: attr_account.as_str().to_owned(),
                            password: password.into(),
                            url: Default::default(),
                            user_data: Default::default(),
                        };

                        let id = SecretId::new_v4();
                        let meta = SecretMeta::new(label, secret.kind());
                        let index_doc =
                            index.prepare(keeper.id(), &id, &meta, &secret);
                        let secret_data = SecretRow::new(id, meta, secret);
                        keeper.create_secret(&secret_data).await?;
                        index.commit(index_doc);
                    }
                }
            }
        }

        keeper.lock();

        Ok(keeper.into())
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
    pub name: String,
    /// Path to the keychain.
    pub path: PathBuf,
}

/// Attempt to find keychains by searching the standard
/// user directory (`~/Library/Keychains`).
pub fn user_keychains() -> Result<Vec<UserKeychain>> {
    let mut keychains = Vec::new();
    let args = vec!["list-keychains"];
    let dump = Command::new("security").args(args).output()?;
    let reader = BufReader::new(dump.stdout.as_slice());

    for line in reader.lines() {
        let mut line = line?;
        line = line.trim().to_string();

        let unquoted =
            line.trim_start_matches('"').trim_end_matches('"').trim();

        // Ignore empty lines and check it is in the user directory.
        //
        // Note we cannot test against home_dir() because for a sandboxed
        // application the home directory is not the same as the user's home
        // directory.
        //
        // By testing for /Users we can ignore system keychains.
        if !unquoted.is_empty() && unquoted.starts_with("/Users") {
            let path = PathBuf::from(unquoted);
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

    #[cfg(feature = "interactive-keychain-tests")]
    use crate::{crypto::AccessKey, vault::VaultBuilder};

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
    fn keychain_list() -> Result<()> {
        let results = user_keychains()?;
        assert!(!results.is_empty());
        Ok(())
    }

    #[test]
    fn keychain_dump() -> Result<()> {
        let keychain = find_test_keychain()?;
        let source = dump_keychain(keychain.path, false)?;
        assert!(!source.is_empty());
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "interactive-keychain-tests")]
    async fn keychain_import_autofill() -> Result<()> {
        use crate::vault::BuilderCredentials;
        let keychain = find_test_keychain()?;
        let password = "mock-password".to_owned().into();
        let data_dump =
            KeychainImport::import_data(&keychain, Some(password))?;
        assert!(data_dump.is_some());

        let vault_password: SecretString =
            "mock-vault-password".to_owned().into();

        let vault = VaultBuilder::new()
            .build(BuilderCredentials::Password(vault_password.clone(), None))
            .await?;

        let vault = KeychainImport
            .convert(
                data_dump.unwrap(),
                vault,
                &AccessKey::Password(vault_password.clone()),
            )
            .await?;

        assert_eq!(2, vault.len());

        // Assert on the data
        let keys: Vec<_> = vault.keys().copied().collect();
        let mut keeper = Gatekeeper::new(vault);
        keeper.unlock(&AccessKey::Password(vault_password)).await?;

        for key in &keys {
            if let Some((_meta, secret, _)) = keeper.read_secret(key).await? {
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