#[cfg(all(test, target_os = "macos"))]
mod test {
    use anyhow::Result;
    use keychain_parser::{unescape_octal, KeychainParser};

    #[test]
    fn keychain_unescape_octal() -> Result<()> {
        let expected = include_str!(
            "../../../fixtures/migrate/plist-data-unescaped.txt"
        );
        let contents =
            include_str!("../../../fixtures/migrate/plist-data-escaped.txt");
        let plist = unescape_octal(&contents)?;
        assert_eq!(&expected, &plist);
        Ok(())
    }

    #[test]
    fn keychain_parse_basic() -> Result<()> {
        let contents = include_str!("../../../fixtures/migrate/sos-mock.txt");
        let parser = KeychainParser::new(&contents);
        let list = parser.parse()?;

        let password_entry =
            list.find_generic_password("test password", "test account");
        assert!(password_entry.is_some());

        let note_entry = list.find_generic_note("test note");
        assert!(note_entry.is_some());
        Ok(())
    }

    #[test]
    fn keychain_parse_certificate() -> Result<()> {
        let contents =
            include_str!("../../../fixtures/migrate/mock-certificate.txt",);
        let parser = KeychainParser::new(&contents);
        let _list = parser.parse()?;
        Ok(())
    }

    #[test]
    fn keychain_parse_data() -> Result<()> {
        let contents =
            include_str!("../../../fixtures/migrate/sos-mock-data.txt",);
        let parser = KeychainParser::new(&contents);
        let list = parser.parse()?;

        let password_entry =
            list.find_generic_password("test password", "test account");
        assert!(password_entry.is_some());

        let password_data =
            password_entry.as_ref().unwrap().generic_data()?;
        assert_eq!("mock-password-value", password_data.unwrap());

        let note_entry = list.find_generic_note("test note");
        assert!(note_entry.is_some());

        let note_data = note_entry.as_ref().unwrap().generic_data()?;
        assert_eq!("mock-secure-note-value", note_data.unwrap());

        Ok(())
    }
}
