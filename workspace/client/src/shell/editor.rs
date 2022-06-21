use std::{
    collections::HashMap,
    path::Path,
    process::{Command, ExitStatus},
};

use sha3::{Digest, Keccak256};
use sos_core::secret::{Secret, SecretMeta};
use tempfile::Builder;

use crate::{Error, Result};

#[derive(Debug)]
pub struct EditResult {
    changed: bool,
    secret_meta: SecretMeta,
    secret: Secret,
}

/// Spawn the editor passing the file path and wait for it to exit.
fn spawn_editor<P: AsRef<Path>>(cmd: String, file: P) -> Result<ExitStatus> {
    let mut child = Command::new(cmd)
        .arg(&*file.as_ref().to_string_lossy())
        .spawn()?;
    Ok(child.wait()?)
}

fn to_bytes(secret: &Secret) -> Result<(Vec<u8>, &str)> {
    Ok(match secret {
        Secret::Note(text) => (text.as_bytes().to_vec(), ".txt"),
        Secret::List(list) => (serde_json::to_vec(list)?, ".json"),
        _ => todo!(),
    })
}

fn from_bytes(secret: &Secret, content: Vec<u8>) -> Result<Secret> {
    Ok(match secret {
        Secret::Note(_) => {
            Secret::Note(std::str::from_utf8(&content)?.to_string())
        }
        Secret::List(_) => {
            let list: HashMap<String, String> =
                serde_json::from_slice(&content)?;
            Secret::List(list)
        }
        _ => todo!(),
    })
}

/// Edit a secret.
pub fn edit(secret_meta: SecretMeta, secret: Secret) -> Result<EditResult> {
    let editor_cmd = std::env::var("EDITOR").unwrap_or_else(|_| "vim".into());

    let (content, suffix) = to_bytes(&secret)?;
    let hash = Keccak256::digest(&content);
    let mut file = Builder::new().suffix(suffix).tempfile()?;
    std::fs::write(file.path(), content)?;

    let status = spawn_editor(editor_cmd, file.path())?;
    let result = if status.success() {
        let content = std::fs::read(file.path())?;
        let edited_hash = Keccak256::digest(&content);

        if edited_hash == hash {
            Ok(EditResult {
                changed: false,
                secret_meta,
                secret,
            })
        } else {
            let edited_secret = from_bytes(&secret, content)?;
            Ok(EditResult {
                changed: true,
                secret_meta,
                secret: edited_secret,
            })
        }
    } else {
        // Use default exit code if one is not available
        // for example if the command was terminated by a signal
        Err(Error::EditorExit(status.code().unwrap_or_else(|| -1)))
    };

    file.close()?;

    Ok(result?)
}
