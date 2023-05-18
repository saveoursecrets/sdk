//! Spawn an editor to edit a secret.
//!
//! VIM users should use `set nofixendofline` in their .vimrc
//! to prevent an appended newline changing the file automatically.
//!
use std::{
    borrow::Cow,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use secrecy::ExposeSecret;
use sos_sdk::{
    secrecy,
    sha3::{Digest, Keccak256},
    vault::secret::Secret,
    vcard4::Vcard,
};
use tempfile::Builder;

use crate::{Error, Result, TARGET};

/// The result of editing a secret.
///
/// A borrowed value indicates that no changes were made
/// whilst an owned value indicates the user made some edits.
pub type EditSecretResult<'a> = Cow<'a, Secret>;

/// Spawn the editor passing the file path and wait for it to exit.
fn spawn_editor<P: AsRef<Path>>(cmd: String, file: P) -> Result<ExitStatus> {
    let mut child = Command::new(cmd)
        .arg(&*file.as_ref().to_string_lossy())
        .spawn()?;
    Ok(child.wait()?)
}

/// Convert the secret to bytes to be written to the tempfile.
fn to_bytes(secret: &Secret) -> Result<(Vec<u8>, String)> {
    Ok(match secret {
        Secret::Note { text, .. } => {
            (text.expose_secret().as_bytes().to_vec(), ".txt".to_string())
        }
        Secret::List { .. }
        | Secret::Account { .. }
        | Secret::Pem { .. }
        | Secret::Totp { .. }
        | Secret::Card { .. }
        | Secret::Bank { .. }
        | Secret::Password { .. }
        | Secret::Link { .. }
        | Secret::Identity { .. } => {
            (serde_json::to_vec_pretty(secret)?, ".json".to_string())
        }
        Secret::File { name, buffer, .. } => {
            let file_path = PathBuf::from(name);
            let suffix = if let Some(ext) = file_path.extension() {
                format!(".{}", ext.to_string_lossy())
            } else {
                ".txt".to_string()
            };
            (buffer.expose_secret().to_vec(), suffix)
        }
        Secret::Page { document, .. } => (
            document.expose_secret().as_bytes().to_vec(),
            ".md".to_string(),
        ),
        Secret::Signer { .. } | Secret::Age { .. } => {
            // TODO: handle this more gracefully
            todo!("secret type is not editable (yet!)")
        }
        Secret::Contact { vcard, .. } => {
            (vcard.to_string().as_bytes().to_vec(), ".txt".to_string())
        }
    })
}

/// Convert back from the tempfile bytes to a secret.
fn from_bytes(secret: &Secret, content: &[u8]) -> Result<Secret> {
    Ok(match secret {
        Secret::Note { user_data, .. } => Secret::Note {
            text: secrecy::Secret::new(
                std::str::from_utf8(content)?
                    //.trim_end_matches('\n')
                    .to_owned(),
            ),
            user_data: user_data.clone(),
        },
        Secret::List { .. }
        | Secret::Account { .. }
        | Secret::Pem { .. }
        | Secret::Totp { .. }
        | Secret::Card { .. }
        | Secret::Bank { .. }
        | Secret::Password { .. }
        | Secret::Link { .. }
        | Secret::Identity { .. } => {
            serde_json::from_slice::<Secret>(content)?
        }
        Secret::File {
            name,
            mime,
            checksum,
            user_data,
            ..
        } => Secret::File {
            name: name.clone(),
            mime: mime.clone(),
            buffer: secrecy::Secret::new(content.to_vec()),
            checksum: *checksum,
            external: false,
            size: content.len() as u64,
            path: None,
            user_data: user_data.clone(),
        },
        Secret::Page {
            title,
            mime,
            user_data,
            ..
        } => Secret::Page {
            title: title.clone(),
            mime: mime.clone(),
            document: secrecy::Secret::new(
                std::str::from_utf8(content)?.to_owned(),
            ),
            user_data: user_data.clone(),
        },
        Secret::Signer { .. } | Secret::Age { .. } => {
            // TODO: handle this more gracefully
            todo!("secret type is not editable (yet!)")
        }
        Secret::Contact { user_data, .. } => {
            let value = std::str::from_utf8(content)?;
            let vcard: Vcard = value.try_into()?;
            Secret::Contact {
                vcard: Box::new(vcard),
                user_data: user_data.clone(),
            }
        }
    })
}

fn editor<'a>(content: &'a [u8], suffix: &str) -> Result<Cow<'a, [u8]>> {
    let editor_cmd = std::env::var("EDITOR").unwrap_or_else(|_| "vim".into());
    let hash = digest(content);
    let file = Builder::new().suffix(suffix).tempfile()?;
    std::fs::write(file.path(), content)?;
    let status = spawn_editor(editor_cmd, file.path())?;
    let result = if status.success() {
        let edited_content = std::fs::read(file.path())?;
        let edited_hash = digest(&edited_content);
        if edited_hash == hash {
            Ok(Cow::Borrowed(content))
        } else {
            Ok(Cow::Owned(edited_content))
        }
    } else {
        // Use default exit code if one is not available
        // for example if the command was terminated by a signal
        Err(Error::EditorExit(status.code().unwrap_or(-1)))
    };
    file.close()?;
    result
}

fn digest<B: AsRef<[u8]>>(bytes: B) -> Vec<u8> {
    Keccak256::digest(bytes).to_vec()
}

/// Edit a secret.
pub fn edit(secret: &Secret) -> Result<EditSecretResult<'_>> {
    let (content, suffix) = to_bytes(secret)?;
    edit_secret(secret, content, &suffix)
}

fn edit_secret<'a>(
    secret: &'a Secret,
    content: Vec<u8>,
    suffix: &str,
) -> Result<EditSecretResult<'a>> {
    let result = editor(&content, suffix)?;
    match result {
        Cow::Borrowed(_) => Ok(Cow::Borrowed(secret)),
        Cow::Owned(b) => {
            match from_bytes(secret, &b) {
                Ok(edited_secret) => Ok(Cow::Owned(edited_secret)),
                // Parse error, launch the editor again so the user
                // gets the chance to correct the mistake.
                Err(e) => {
                    tracing::error!(
                        target: TARGET,
                        "secret data is not valid: {}",
                        e
                    );
                    return edit_secret(secret, content, suffix);
                }
            }
        }
    }
}

/// Edit text.
pub fn edit_text(text: &str) -> Result<Cow<str>> {
    let result = editor(text.as_bytes(), ".txt")?;
    match result {
        Cow::Borrowed(_) => Ok(Cow::Borrowed(text)),
        Cow::Owned(b) => Ok(Cow::Owned(String::from_utf8(b)?)),
    }
}
