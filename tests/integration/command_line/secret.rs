use super::*;
use anyhow::Result;
use rexpect::spawn;
use secrecy::SecretString;
use sos_net::sdk::{
    account::UserPaths, constants::DEFAULT_VAULT_NAME,
    passwd::diceware::generate_passphrase, secrecy::ExposeSecret, vfs,
};
use std::{ops::DerefMut, path::PathBuf};

pub fn add_note(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    if is_ci() && repl.is_none() {
        helpers::set_note_ci_vars();
    }

    let cmd =
        format!("{} secret add note -a {} -n {}", exe, address, NOTE_NAME);
    run!(repl, cmd, true, |ps: &mut PtySession,
                           prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        if !is_ci() {
            ps.exp_regex(">> ")?;
            ps.send_line(NOTE_VALUE)?;
            ps.exp_regex(">> ")?;
            ps.send_control('d')?;
        }
        ps.exp_regex("Secret created")?;
        Ok(())
    });

    if is_ci() && repl.is_none() {
        helpers::clear_note_ci_vars();
    }

    Ok(())
}

pub fn add_file(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let file = PathBuf::from("tests/fixtures/sample.heic").canonicalize()?;
    let cmd = format!(
        "{} secret add file -a {} -n {} {}",
        exe,
        address,
        FILE_NAME,
        file.display()
    );
    run!(repl, cmd, true, |ps: &mut PtySession,
                           prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        ps.exp_regex("Secret created")?;
        Ok(())
    });

    Ok(())
}

pub fn add_login(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let (account_password, _) = generate_passphrase()?;

    if is_ci() && repl.is_none() {
        helpers::set_login_ci_vars(&account_password);
    }

    let cmd =
        format!("{} secret add login -a {} -n {}", exe, address, LOGIN_NAME);
    run!(repl, cmd, true, |ps: &mut PtySession,
                           prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        if !is_ci() {
            ps.exp_regex("Username:")?;
            ps.send_line(LOGIN_SERVICE_NAME)?;

            ps.exp_regex("Website:")?;
            ps.send_line(LOGIN_URL)?;

            ps.exp_regex("Password:")?;
            ps.send_line(account_password.expose_secret())?;
        }
        ps.exp_regex("Secret created")?;
        Ok(())
    });

    if is_ci() && repl.is_none() {
        helpers::clear_login_ci_vars();
    }

    Ok(())
}

pub fn add_list(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let (value_1, _) = generate_passphrase()?;
    let (value_2, _) = generate_passphrase()?;

    if is_ci() && repl.is_none() {
        helpers::set_list_ci_vars(&value_1, &value_2);
    }

    let cmd =
        format!("{} secret add list -a {} -n {}", exe, address, LIST_NAME);
    run!(repl, cmd, true, |ps: &mut PtySession,
                           prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        if !is_ci() {
            ps.exp_regex("Key:")?;
            ps.send_line(LIST_KEY_1)?;

            ps.exp_regex("Value:")?;
            ps.send_line(value_1.expose_secret())?;

            ps.exp_regex("Add more")?;
            ps.send_line("y")?;

            ps.exp_regex("Key:")?;
            ps.send_line(LIST_KEY_2)?;

            ps.exp_regex("Value:")?;
            ps.send_line(value_2.expose_secret())?;

            ps.exp_regex("Add more")?;
            ps.send_line("n")?;
        }
        ps.exp_regex("Secret created")?;
        Ok(())
    });

    if is_ci() && repl.is_none() {
        helpers::clear_list_ci_vars();
    }

    Ok(())
}

pub fn list(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!("{} secret list -a {}", exe, address);
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd = format!("{} secret list --verbose -a {}", exe, address);
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd = format!("{} secret list --all -a {}", exe, address);
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd = format!("{} secret list --favorites -a {}", exe, address);
    read_until_eof(cmd, Some(password), repl)
}

pub fn get(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!("{} secret get -a {} {}", exe, address, NOTE_NAME);
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd = format!("{} secret get -a {} {}", exe, address, FILE_NAME);
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd = format!("{} secret get -a {} {}", exe, address, LOGIN_NAME);
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd = format!("{} secret get -a {} {}", exe, address, LIST_NAME);
    read_until_eof(cmd, Some(password), repl)
}

pub fn cp(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!("{} secret cp -a {} {}", exe, address, NOTE_NAME);
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd = format!("{} secret cp -a {} {}", exe, address, FILE_NAME);
    read_until_eof(cmd, Some(password), repl)
}

pub fn info(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!("{} secret info -a {} {}", exe, address, NOTE_NAME);
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd =
        format!("{} secret info --debug -a {} {}", exe, address, NOTE_NAME);
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd =
        format!("{} secret info --json -a {} {}", exe, address, NOTE_NAME);
    read_until_eof(cmd, Some(password), repl)
}

pub fn tags(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let tags = "foo,bar,qux";

    let cmd = format!(
        "{} secret tags add -a {} --tags {} {}",
        exe, address, tags, NOTE_NAME
    );
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd =
        format!("{} secret tags list -a {} {}", exe, address, NOTE_NAME);
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd = format!(
        "{} secret tags rm -a {} --tags {} {}",
        exe, address, "foo,bar", NOTE_NAME
    );
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd =
        format!("{} secret tags clear -a {} {}", exe, address, NOTE_NAME);
    read_until_eof(cmd, Some(password), repl)
}

pub fn favorite(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    // Add to favorites with first toggle
    let cmd = format!("{} secret favorite -a {} {}", exe, address, NOTE_NAME);
    read_until_eof(cmd, Some(password), repl.clone())?;

    // Remove from favorites with second toggle
    let cmd = format!("{} secret favorite -a {} {}", exe, address, NOTE_NAME);
    read_until_eof(cmd, Some(password), repl)
}

pub fn rename(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!(
        "{} secret rename -a {} --name {} {}",
        exe, address, NEW_NOTE_NAME, NOTE_NAME
    );
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd = format!(
        "{} secret rename -a {} --name {} {}",
        exe, address, NOTE_NAME, NEW_NOTE_NAME
    );
    read_until_eof(cmd, Some(password), repl)
}

pub fn mv(
    exe: &str,
    address: &str,
    password: &SecretString,
    account_name: &str,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let target_folder = "moved-secret-folder";

    let new_prompt = format_prompt(account_name, target_folder);
    let renamed = repl.clone().map(|(s, _p)| (s, &new_prompt[..]));

    // Create temporary folder
    let cmd = format!("{} folder new -a {} {}", exe, address, target_folder);
    run!(repl, cmd, true, |ps: &mut PtySession,
                           prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        ps.exp_regex("Folder created")?;
        Ok(())
    });

    // Move to the new folder
    let cmd = format!(
        "{} secret move -a {} --target {} {}",
        exe, address, target_folder, NOTE_NAME
    );
    run!(repl, cmd, true, |ps: &mut PtySession,
                           prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        ps.exp_regex("Secret moved")?;
        Ok(())
    });

    // Move back to the default folder
    let cmd = format!(
        "{} secret move -a {} --target {} --folder {} {}",
        exe, address, DEFAULT_VAULT_NAME, target_folder, NOTE_NAME
    );
    run!(renamed, cmd, true, |ps: &mut PtySession,
                              prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        ps.exp_regex("Secret moved")?;
        Ok(())
    });

    // Clean up the temporary folder
    let cmd =
        format!("{} folder remove -a {} {}", exe, address, target_folder);
    run!(repl, cmd, true, |ps: &mut PtySession,
                           prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }

        if !is_ci() {
            ps.exp_regex("Delete folder")?;
            ps.send_line("y")?;
        }

        ps.exp_regex("Folder deleted")?;
        Ok(())
    });

    Ok(())
}

pub fn comment(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    // Set a comment
    let cmd = format!(
        "{} secret comment -a {} --text {} {}",
        exe, address, "mock-comment", NOTE_NAME
    );
    read_until_eof(cmd, Some(password), repl.clone())?;

    // Clear the comment
    let cmd = format!(
        "{} secret comment -a {} --text '' {}",
        exe, address, NOTE_NAME
    );
    read_until_eof(cmd, Some(password), repl)
}

pub fn archive_unarchive(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    // Move to archive
    let cmd = format!("{} secret archive -a {} {}", exe, address, NOTE_NAME);
    run!(repl, cmd, true, |ps: &mut PtySession,
                           prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        ps.exp_regex("Moved to archive")?;
        Ok(())
    });

    // Restore from archive
    let cmd =
        format!("{} secret unarchive -a {} {}", exe, address, NOTE_NAME);
    run!(repl, cmd, true, |ps: &mut PtySession,
                           prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        ps.exp_regex("Restored from archive")?;
        Ok(())
    });

    Ok(())
}

pub async fn download(
    exe: &str,
    address: &str,
    password: &SecretString,
    account_name: &str,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let data_dir = UserPaths::data_dir()?;
    let output = data_dir.join(format!("sample-{}.heic", account_name));

    let cmd = format!(
        "{} secret download -a {} {} {}",
        exe,
        address,
        FILE_NAME,
        output.display()
    );
    run!(repl, cmd, true, |ps: &mut PtySession,
                           prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        ps.exp_regex("Download complete")?;
        Ok(())
    });
    assert!(vfs::try_exists(&output).await?);

    let cmd = format!(
        "{} secret download -a {} --force {} {}",
        exe,
        address,
        FILE_NAME,
        output.display()
    );
    run!(repl, cmd, true, |ps: &mut PtySession,
                           prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        ps.exp_regex("Download complete")?;
        Ok(())
    });
    assert!(vfs::try_exists(&output).await?);

    Ok(())
}

pub async fn attach(
    exe: &str,
    address: &str,
    password: &SecretString,
    account_name: &str,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let data_dir = UserPaths::data_dir()?;
    let input = PathBuf::from("tests/fixtures/sample.heic").canonicalize()?;
    let output =
        data_dir.join(format!("sample-attachment-{}.heic", account_name));

    // Create file attachment
    let cmd = format!(
        "{} secret attach add file -a {} --name {} --path {} {}",
        exe,
        address,
        FILE_ATTACHMENT,
        input.display(),
        NOTE_NAME
    );
    {
        let repl = repl.clone();
        run!(repl, cmd, true, |ps: &mut PtySession,
                               prompt: Option<&str>|
         -> Result<()> {
            if !is_ci() && prompt.is_none() {
                ps.exp_regex("Password:")?;
                ps.send_line(password.expose_secret())?;
            }
            ps.exp_regex("Secret updated")?;
            Ok(())
        });
    }

    // Create note attachment
    if is_ci() && repl.is_none() {
        helpers::set_note_ci_vars();
    }
    let cmd = format!(
        "{} secret attach add note -a {} --name {} {}",
        exe, address, NOTE_ATTACHMENT, NOTE_NAME
    );
    {
        let repl = repl.clone();
        run!(repl, cmd, true, |ps: &mut PtySession,
                               prompt: Option<&str>|
         -> Result<()> {
            if !is_ci() && prompt.is_none() {
                ps.exp_regex("Password:")?;
                ps.send_line(password.expose_secret())?;
            }

            if !is_ci() {
                ps.exp_regex(">> ")?;
                ps.send_line(NOTE_VALUE)?;
                ps.exp_regex(">> ")?;
                ps.send_control('d')?;
            }

            ps.exp_regex("Secret updated")?;
            Ok(())
        });
    }

    if is_ci() {
        helpers::clear_note_ci_vars();
    }

    // Create link attachment
    if is_ci() {
        helpers::set_link_ci_vars();
    }
    let cmd = format!(
        "{} secret attach add link -a {} --name {} {}",
        exe, address, LINK_ATTACHMENT, NOTE_NAME
    );

    {
        let repl = repl.clone();
        run!(repl, cmd, true, |ps: &mut PtySession,
                               prompt: Option<&str>|
         -> Result<()> {
            if !is_ci() && prompt.is_none() {
                ps.exp_regex("Password:")?;
                ps.send_line(password.expose_secret())?;
            }

            if !is_ci() {
                ps.exp_regex("URL:")?;
                ps.send_line(LINK_VALUE)?;
            }

            ps.exp_regex("Secret updated")?;
            Ok(())
        });
    }

    if is_ci() {
        helpers::clear_link_ci_vars();
    }

    // Create password attachment
    let (attachment_password, _) = generate_passphrase()?;
    if is_ci() {
        helpers::set_password_ci_vars(&attachment_password);
    }
    let cmd = format!(
        "{} secret attach add password -a {} --name {} {}",
        exe, address, PASSWORD_ATTACHMENT, NOTE_NAME
    );

    {
        let repl = repl.clone();
        run!(repl, cmd, true, |ps: &mut PtySession,
                               prompt: Option<&str>|
         -> Result<()> {
            if !is_ci() && prompt.is_none() {
                ps.exp_regex("Password:")?;
                ps.send_line(password.expose_secret())?;
            }

            // Hack for this test failing (incorrectly) sporadically
            std::thread::sleep(std::time::Duration::from_millis(25));

            if !is_ci() {
                ps.exp_regex("Password:")?;
                ps.send_line(attachment_password.expose_secret())?;
            }

            ps.exp_regex("Secret updated")?;
            Ok(())
        });
    }

    if is_ci() {
        helpers::clear_password_ci_vars();
    }

    // Get an attachment
    let cmd = format!(
        "{} secret attach get -a {} {} {}",
        exe, address, NOTE_NAME, NOTE_ATTACHMENT,
    );
    read_until_eof(cmd, Some(password), repl.clone())?;

    // List attachments
    let cmd =
        format!("{} secret attach ls -a {} {}", exe, address, NOTE_NAME,);
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd = format!(
        "{} secret attach ls --verbose -a {} {}",
        exe, address, NOTE_NAME,
    );
    read_until_eof(cmd, Some(password), repl.clone())?;

    // Download file attachment
    let cmd = format!(
        "{} secret attach download -a {} {} {} {}",
        exe,
        address,
        NOTE_NAME,
        FILE_ATTACHMENT,
        output.display()
    );
    {
        let repl = repl.clone();
        run!(repl, cmd, true, |ps: &mut PtySession,
                               prompt: Option<&str>|
         -> Result<()> {
            if !is_ci() && prompt.is_none() {
                ps.exp_regex("Password:")?;
                ps.send_line(password.expose_secret())?;
            }
            ps.exp_regex("Download complete")?;
            Ok(())
        });
    }
    assert!(vfs::try_exists(&output).await?);

    // Remove an attachment
    let cmd = format!(
        "{} secret attach remove -a {} {} {}",
        exe, address, NOTE_NAME, NOTE_ATTACHMENT,
    );
    read_until_eof(cmd, Some(password), repl)
}

pub fn remove(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!("{} secret remove -a {} {}", exe, address, NOTE_NAME);
    run!(repl, cmd, true, |ps: &mut PtySession,
                           prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        if !is_ci() {
            ps.exp_regex("Delete secret")?;
            ps.send_line("y")?;
        }
        ps.exp_regex("Secret deleted")?;
        Ok(())
    });

    Ok(())
}
