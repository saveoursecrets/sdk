use sos_sdk::{vault::secret::SecretRef, vcard4};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(r#"account "{0}" already exists"#)]
    AccountExists(String),

    #[error(r#"folder "{0}" already exists"#)]
    FolderExists(String),

    #[error(r#"folder "{0}" not found"#)]
    FolderNotFound(String),

    #[error(r#"device "{0}" not found"#)]
    DeviceNotFound(String),

    #[error("archive folder not found")]
    NoArchiveFolder,

    #[error("password is not strong enough")]
    PasswordStrength,

    #[error("passwords do not match")]
    PasswordMismatch,

    #[error(r#"no accounts found, use "account new" to create an account"#)]
    NoAccounts,

    #[error("could not infer account, use --account to specify account")]
    NoAccountFound,

    #[error("account required, specify target account name")]
    ExplicitAccount,

    #[error("could not find folder, use --folder to specify folder")]
    NoFolderFound,

    #[error("permission denied; default folder cannot be deleted")]
    NoRemoveDefaultFolder,

    #[error("operation is only permitted on the current account")]
    NotShellAccount,

    #[error("could not find contacts folder")]
    NoContactsFolder,

    #[error("could not determine cache directory")]
    NoCache,

    #[error("path {0} is not a directory")]
    NotDirectory(PathBuf),

    #[error("path {0} is not a file")]
    NotFile(PathBuf),

    #[error("account {0} does not exist")]
    NoAccount(String),

    #[error("could not determine path for local cache directory")]
    NoCacheDir,

    #[error("file {0} already exists")]
    FileExists(PathBuf),

    #[error("path {0} does not have a file name")]
    FileName(PathBuf),

    #[error("failed to create account, got status code {0}")]
    AccountCreate(u16),

    #[error("no folder was found")]
    NoVault,

    #[error(r#"no folder selected, run "use" to select a folder"#)]
    NoVaultSelected,

    #[error(r#"secret "{0}" not found"#)]
    SecretNotAvailable(SecretRef),

    #[error("editor command did not exit successfully, status {0}")]
    EditorExit(i32),

    /// Error generated when a passphrase is not valid.
    #[error("passphrase is not valid")]
    InvalidPassphrase,

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Core(#[from] sos_sdk::Error),

    #[error(transparent)]
    Node(#[from] sos_net::Error),

    #[error(transparent)]
    NodeClient(#[from] sos_net::client::Error),

    #[error(transparent)]
    UrlParse(#[from] sos_sdk::url::ParseError),

    #[error(transparent)]
    Clap(#[from] clap::Error),

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    Readline(#[from] rustyline::error::ReadlineError),

    #[error(transparent)]
    ShellWords(#[from] shell_words::ParseError),

    #[error(transparent)]
    Vcard(#[from] vcard4::Error),

    #[error(transparent)]
    Server(#[from] sos_net::server::Error),

    #[error(transparent)]
    Peer(#[from] sos_net::peer::Error),
}

impl Error {
    pub fn is_interrupted(&self) -> bool {
        matches!(
            self,
            Error::Readline(rustyline::error::ReadlineError::Interrupted)
        )
    }
}
