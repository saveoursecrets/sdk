use sos_core::secret::SecretRef;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("path {0} is not a directory")]
    NotDirectory(PathBuf),

    #[error("path {0} is not a file")]
    NotFile(PathBuf),

    #[error("file {0} already exists")]
    FileExists(PathBuf),

    #[error("path {0} does not have a file name")]
    FileName(PathBuf),

    #[error("could not determine local data directory")]
    NoDataLocalDir,

    #[error("failed to create account, got status code {0}")]
    AccountCreate(u16),

    #[error("expecting an x-change-sequence header")]
    ChangeSequenceHeader,

    #[error(r#"vault "{0}" not found, run "vaults" to load the vault list"#)]
    VaultNotAvailable(SecretRef),

    #[error("failed to unlock vault")]
    VaultUnlockFail,

    #[error(r#"no vault selected, run "use" to select a vault"#)]
    NoVaultSelected,

    #[error(r#"secret "{0}" not found"#)]
    SecretNotAvailable(SecretRef),

    #[error("failed to create vault, got status code {0}")]
    VaultCreate(u16),

    #[error("failed to delete vault, got status code {0}")]
    VaultRemove(u16),

    #[error("failed to set vault name, got status code {0}")]
    SetVaultName(u16),

    #[error("failed to add secret, got status code {0}")]
    AddSecret(u16),

    #[error("failed to set secret, got status code {0}")]
    SetSecret(u16),

    #[error("editor command did not exit successfully, status {0}")]
    EditorExit(i32),

    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),

    #[error(transparent)]
    ToStr(#[from] reqwest::header::ToStrError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Keystore(#[from] web3_keystore::KeyStoreError),

    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error(transparent)]
    Core(#[from] sos_core::Error),

    #[error(transparent)]
    Readline(#[from] sos_readline::Error),

    #[error(transparent)]
    Http(#[from] reqwest::Error),

    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    #[error(transparent)]
    EventSource(#[from] reqwest_eventsource::Error),

    #[error(transparent)]
    Clap(#[from] clap::Error),

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    ShellWords(#[from] shell_words::ParseError),
}
