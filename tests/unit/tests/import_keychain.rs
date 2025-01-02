#[cfg(all(test, target_os = "macos"))]
mod test {
    use anyhow::Result;
    use sos_migrate::import::keychain::*;

    #[cfg(feature = "interactive-keychain-tests")]
    use sos_sdk::{crypto::AccessKey, vault::VaultBuilder};

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
        use sos_sdk::vault::BuilderCredentials;
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
