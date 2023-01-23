//! Import from keychain access.
use std::{
    io::{BufWriter, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc::{channel, Receiver},
};

use security_framework::{
    item::{ItemClass, ItemSearchOptions},
    os::macos::item::ItemSearchOptionsExt,
    os::macos::keychain::SecKeychain,
};

use crate::{Error, Result};

/// File extension for keychain files.
const KEYCHAIN_DB: &str = "keychain-db";

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

/*
/// Verify the password for a keychain.
pub fn verify_password(keychain: SecKeychain, password: &str) -> Result<()> {
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

    Ok(())
}
*/

/// Attempt to autofill the security agent password prompts
/// with the given password using some Applescript.
///
/// Requires that the Accessibility permission has been given
/// to the application in System Preferences.
pub fn spawn_password_autofill_osascript(rx: Receiver<bool>, password: String) {
    std::thread::spawn(move || {
        let mut child = Command::new("osascript")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let mut writer = BufWriter::new(&mut stdin);
        let script = format!(r#"
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
"#, password);
        writer
            .write_all(script.as_bytes())
            .expect("failed to write to child script");

        // Got a signal to kill the process, we need to do this
        // otherwise the applescript keeps running while the SecurityAgent
        // process is closing and keeps trying to steal focus
        std::thread::spawn(move || {
            while let Ok(_) = rx.recv() {
                let _ = child.kill();
                break;
            }
        });
    });
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;

    use security_framework::item::*;
    use security_framework::os::macos::item::ItemSearchOptionsExt;
    use security_framework::os::macos::keychain::SecKeychain;

    #[test]
    fn keychain_import() -> Result<()> {
        // NOTE: the keychain must be located in ~/Library/Keychains
        // NOTE: otherwise searching fails to find any items

        let keychains = user_keychains()?;
        let keychain = keychains.iter()
            .find(|k| k.name == "test-export");

        if keychain.is_none() {
            eprintln!("To test the MacOS keychain export you must have a keychain called `test-export` in ~/Library/Keychains.");
            panic!("keychain test for MacOS not configured");
        }

        let keychain = SecKeychain::open(
            &keychain.as_ref().unwrap().path)?;
        let password = "mock-password-foo";

        //keychain.unlock(None)?;
        
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
