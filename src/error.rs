use sos_net::sdk::{vault::secret::SecretRef, vcard4};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(r#"account "{0}" already exists"#)]
    AccountExists(String),

    #[error(r#"folder "{0}" already exists"#)]
    FolderExists(String),

    #[error(r#"attachment "{0}" already exists"#)]
    FieldExists(String),

    #[error(r#"folder "{0}" not found"#)]
    FolderNotFound(String),

    #[error(r#"device "{0}" not found"#)]
    DeviceNotFound(String),

    #[error(r#"attachment "{0}" not found"#)]
    FieldNotFound(SecretRef),

    #[error(r#"initial sync has errors"#)]
    InitialSync,

    #[error(r#"sync failed"#)]
    SyncFail,

    #[error(r#"no servers"#)]
    NoServers,

    #[error(r#"no servers found matching the request"#)]
    NoMatchServers,

    #[error("unable to copy to the clipboard, secret type may not support copy operation")]
    ClipboardCopy,

    #[error("archive folder not found")]
    NoArchiveFolder,

    #[error("not a file secret")]
    NotFileContent,

    #[error("external files cannot be edited")]
    EditExternalFile,

    #[error("invalid URL, please check the syntax")]
    InvalidUrl,

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

    /// Error generated when a file exists and the --force flag
    /// should be used to overwrite the destination.
    #[error("file {0} already exists, use --force to overwrite")]
    FileExistsUseForce(PathBuf),

    #[error("unknown report format '{0}'")]
    UnknownReportFormat(String),

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Core(#[from] sos_net::sdk::Error),

    #[error(transparent)]
    Node(#[from] sos_net::Error),

    #[error(transparent)]
    NodeClient(#[from] sos_net::client::Error),

    #[error(transparent)]
    UrlParse(#[from] sos_net::sdk::url::ParseError),

    #[error(transparent)]
    Clap(#[from] clap::Error),

    /// Error generated converting from UTF8.
    #[error(transparent)]
    Utf8Str(#[from] std::str::Utf8Error),

    /// Error generated converting from UTF8.
    #[error(transparent)]
    Utf8String(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    Readline(#[from] rustyline::error::ReadlineError),

    #[error(transparent)]
    ShellWords(#[from] shell_words::ParseError),

    #[error(transparent)]
    Vcard(#[from] vcard4::Error),

    #[error(transparent)]
    Server(#[from] sos_net::server::Error),

    #[error(transparent)]
    Clipboard(#[from] arboard::Error),

    #[error(transparent)]
    Hex(#[from] sos_net::sdk::hex::FromHexError),

    #[error(transparent)]
    Csv(#[from] csv_async::Error),

    #[error(transparent)]
    Ctrlc(#[from] ctrlc::Error),
}

impl Error {
    pub fn is_interrupted(&self) -> bool {
        matches!(
            self,
            Error::Readline(rustyline::error::ReadlineError::Interrupted)
        )
    }
}
