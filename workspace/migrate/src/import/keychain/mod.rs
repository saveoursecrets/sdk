//! Import from keychain access.
pub mod error;
pub mod parser;

pub use error::Error;

/// Result type for keychain access integration.
pub type Result<T> = std::result::Result<T, Error>;

use std::{
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::{channel, Receiver},
};

use parser::{KeychainList, KeychainParser};
use secrecy::{ExposeSecret, SecretString};

use security_framework::os::macos::keychain::SecKeychain;

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

        //println!("Total items: {}", list.len());

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
                    keychain, password.expose_secret())?;
                return Ok(Some(data))
            } else {
                // User must manually enter the passphrase for each secret 
                let data = dump_keychain(&keychain.path, true)?;
                return Ok(Some(data))
            }
        }
        Ok(None)
    }

    fn dump_data_autofill(
        keychain: &UserKeychain, password: &str) -> Result<String> {
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
pub fn spawn_password_autofill_osascript(
    rx: Receiver<bool>,
    password: &str,
) {
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

    use security_framework::os::macos::keychain::SecKeychain;

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
        use std::sync::mpsc::channel;

        let keychain = find_test_keychain()?;
        let source = dump_keychain(&keychain.path, false)?;
        let password = SecretString::new("mock-password".to_owned());
        let data_dump = KeychainImport::import(
            &keychain, &source, Some(password))?;
        assert!(data_dump.is_some());

        let data = data_dump.unwrap();
        let parser = KeychainParser::new(&data);
        let list = parser.parse()?;

        /*
        let keychain = SecKeychain::open(&keychain.path)?;
        let password = "mock-password";

        let (tx, rx) = channel::<bool>();
        spawn_password_autofill_osascript(rx, password.to_owned());

        let (_, _) = keychain
            .find_generic_password("test password", "test account")?;
        tx.send(true)?;
        */

        /*
        let mut searcher = ItemSearchOptions::new();
        searcher.class(ItemClass::generic_password());
        searcher.load_attributes(true);
        searcher.load_data(true);
        searcher.keychains(&[keychain]);
        searcher.limit(1);

        let (tx, rx) = channel::<bool>();
        spawn_password_autofill_osascript(rx, password.to_owned());

        let results = searcher.search()?;
        for result in results {
            println!("{:#?}", result);
        }
        tx.send(true)?;
        */

        Ok(())
    }
}
