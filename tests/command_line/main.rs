#[cfg(feature = "enable-cli-tests")]
mod cli {
    use anticipate_runner::{InterpreterOptions, ScriptFile};
    use anyhow::Result;
    use std::{
        env::{set_var, var},
        path::Path,
    };

    #[test]
    fn command_line() -> Result<()> {
        prepare_env();

        let specs = vec![
            "tests/command_line/scripts/setup.sh",
            "tests/command_line/scripts/specs/account.sh",
            "tests/command_line/scripts/specs/check.sh",
            "tests/command_line/scripts/specs/device.sh",
            "tests/command_line/scripts/specs/events.sh",
            "tests/command_line/scripts/specs/folder.sh",
            "tests/command_line/scripts/specs/secret.sh",
            "tests/command_line/scripts/specs/security-report.sh",
            "tests/command_line/scripts/specs/server.sh",
            "tests/command_line/scripts/specs/shell.sh",
            "tests/command_line/scripts/specs/preferences.sh",
            "tests/command_line/scripts/specs/audit.sh",
            "tests/command_line/scripts/teardown.sh",
        ];

        for spec in specs {
            run_spec(spec)?;
        }

        Ok(())
    }

    fn run_spec(input_file: impl AsRef<Path>) -> Result<()> {
        let file_name = input_file
            .as_ref()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let echo = var("ANTICIPATE_ECHO").is_ok();
        let script = ScriptFile::parse(input_file)?;
        let mut options = InterpreterOptions::new(15000, echo, false, false);
        options.id = Some(file_name.to_owned());
        script.run(options)?;
        Ok(())
    }

    fn prepare_env() {
        let path = var("PATH").ok().unwrap_or_default();
        let prefix = if var("COVER").ok().is_some() {
            "target/cover/debug"
        } else {
            "target/debug"
        };
        set_var("PATH", format!("{}:{}", prefix, path));

        set_var("BASH_SILENCE_DEPRECATION_WARNING", "1");
        set_var("NO_COLOR", "1");

        set_var("SOS_DATA_DIR", "target/accounts");
        set_var("SOS_PROMPT", "➜ ");
        set_var("SOS_OFFLINE", "1");
        set_var("DEMO_SERVER", "https://demo.saveoursecrets.com");

        set_var("ACCOUNT_NAME", "Demo");
        set_var("ACCOUNT_NAME_ALT", "Demo Account");
        set_var("ACCOUNT_PASSWORD", "demo-test-password-case");
        set_var("ACCOUNT_BACKUP", "target/demo-backup.zip");
        set_var("ACCOUNT_CONTACTS", "tests/fixtures/contacts.vcf");
        set_var("CONTACTS_EXPORT", "target/demo-contacts.vcf");

        set_var("DEFAULT_FOLDER_NAME", "Documents");
        set_var("FOLDER_NAME", "mock-folder");
        set_var("NEW_FOLDER_NAME", "mock-folder-renamed");

        set_var("FILE_INPUT", "tests/fixtures/sample.heic");
        set_var("FILE_OUTPUT", "target/file-download.heic");

        set_var("ATTACH_INPUT", "tests/fixtures/test-file.txt");
        set_var("ATTACH_OUTPUT", "target/attachment-download.txt");

        set_var("NOTE_NAME", "mock note");
        set_var("FILE_NAME", "mock file");
        set_var("LOGIN_NAME", "mock login");
        set_var("LIST_NAME", "mock list");

        set_var("LOGIN_SERVICE_NAME", "mock-service");
        set_var("LOGIN_URL", "https://example.com");
        set_var("LOGIN_PASSWORD", "mock-login-password");

        set_var("LIST_NAME", "mock-list");
        set_var("LIST_KEY_1", "SERVICE_1_API");
        set_var("LIST_VALUE_1", "mock-key-1");
        set_var("LIST_KEY_2", "SERVICE_2_API");
        set_var("LIST_VALUE_2", "mock-key-2");

        set_var("FILE_ATTACHMENT", "file-attachment");
        set_var("NOTE_ATTACHMENT", "note-attachment");
        set_var("LINK_ATTACHMENT", "link-attachment");
        set_var("PASSWORD_ATTACHMENT", "password-attachment");
        set_var("LINK_VALUE", "https://example.com");

        set_var(
            "MIGRATE_1PASSWORD",
            "tests/fixtures/migrate/1password-export.csv",
        );
        set_var(
            "MIGRATE_DASHLANE",
            "tests/fixtures/migrate/dashlane-export.zip",
        );
        set_var(
            "MIGRATE_BITWARDEN",
            "tests/fixtures/migrate/bitwarden-export.csv",
        );
        set_var(
            "MIGRATE_FIREFOX",
            "tests/fixtures/migrate/firefox-export.csv",
        );
        set_var("MIGRATE_MACOS", "tests/fixtures/migrate/macos-export.csv");
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use sos_test_utils as test_utils;
