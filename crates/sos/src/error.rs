use sos_net::sdk::{vault::secret::SecretRef, vcard4};
use std::path::PathBuf;
use thiserror::Error;

/// Errors generated by the library.
#[derive(Debug, Error)]
pub enum Error {
    /// Account already exists.
    #[error(r#"account "{0}" already exists"#)]
    AccountExists(String),

    /// Folder already exists.
    #[error(r#"folder "{0}" already exists"#)]
    FolderExists(String),

    /// Attachment already exists.
    #[error(r#"attachment "{0}" already exists"#)]
    FieldExists(String),

    /// Folder not found.
    #[error(r#"folder "{0}" not found"#)]
    FolderNotFound(String),

    /// Device not found.
    #[error(r#"device "{0}" not found"#)]
    DeviceNotFound(String),

    /// Attachment not found.
    #[error(r#"attachment "{0}" not found"#)]
    FieldNotFound(SecretRef),

    /// Error performing an initial sync with a server.
    #[error(r#"initial sync has errors: {0}"#)]
    InitialSync(sos_net::Error),

    /// Could not find an authenticator folder.
    #[error("could not find an authenticator folder")]
    NoAuthenticatorFolder,

    /// Sync failed.
    #[error(r#"sync failed"#)]
    SyncFail,

    /// No servers.
    #[error(r#"no servers"#)]
    NoServers,

    /// No matching servers.
    #[error(r#"no servers found matching the request"#)]
    NoMatchServers,

    /// Failed to copy to the clipboard.
    #[error("unable to copy to the clipboard, secret type may not support copy operation")]
    ClipboardCopy,

    /// Archive folder not found.
    #[error("archive folder not found")]
    NoArchiveFolder,

    /// Not a file secret.
    #[error("not a file secret")]
    NotFileContent,

    /// Attempt to edit an external file.
    #[error("external files cannot be edited")]
    EditExternalFile,

    /// Invalid URL.
    #[error("invalid URL, please check the syntax")]
    InvalidUrl,

    /// Password is not strong enough.
    #[error("password is not strong enough")]
    PasswordStrength,

    /// Passwords do not match.
    #[error("passwords do not match")]
    PasswordMismatch,

    /// No accounts found.
    #[error(r#"no accounts found, use "account new" to create an account"#)]
    NoAccounts,

    /// Could not infer account.
    #[error("could not infer account, use --account to specify account")]
    NoAccountFound,

    /// Explicit account reference is required.
    #[error("account required, specify target account name")]
    ExplicitAccount,

    /// No implicit folder could be found.
    #[error("could not find folder, use --folder to specify folder")]
    NoFolderFound,

    /// Refusing to remove the default folder.
    #[error("permission denied; default folder cannot be deleted")]
    NoRemoveDefaultFolder,

    /// Not the current account when operating in a shell context.
    #[error("operation is only permitted on the current account")]
    NotShellAccount,

    /// Could not find contacts folder.
    #[error("could not find contacts folder")]
    NoContactsFolder,

    /// Unable to determine the cache storage directory.
    #[error("could not determine cache directory")]
    NoCache,

    /// Not a directory.
    #[error("path '{0}' is not a directory")]
    NotDirectory(PathBuf),

    /// Not a file.
    #[error("path '{0}' is not a file")]
    NotFile(PathBuf),

    /// Account does not exist.
    #[error("account {0} does not exist")]
    NoAccount(String),

    /// File already exists.
    #[error("file '{0}' already exists")]
    FileExists(PathBuf),

    /// Path requires a file name.
    #[error("path {0} does not have a file name")]
    FileName(PathBuf),

    /// Unable to create an account on a server.
    #[error("failed to create account, got status code {0}")]
    AccountCreate(u16),

    /*
    /// No vault was found.
    #[error("no folder was found")]
    NoVault,
    */
    /// No folder selected.
    #[error(r#"no folder selected, run "use" to select a folder"#)]
    NoVaultSelected,

    /// Secret not found.
    #[error(r#"secret "{0}" not found"#)]
    SecretNotAvailable(SecretRef),

    /// Editor did not exist successfully.
    #[error("editor command did not exit successfully, status {0}")]
    EditorExit(i32),

    /// Error generated when a passphrase is not valid.
    #[error("password is not valid")]
    InvalidPassphrase,

    /// Error generated when a file exists and the --force flag
    /// should be used to overwrite the destination.
    #[error("file {0} already exists, use --force to overwrite")]
    FileExistsUseForce(PathBuf),

    /// Unknown report format.
    #[error("unknown report format '{0}'")]
    UnknownReportFormat(String),

    /// Unknown path filter.
    #[error("unknown path filter '{0}'")]
    UnknownPathFilter(String),

    /// Error generated converting to fixed length slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated by the [std::io] module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Error generated by the SDK library.
    #[error(transparent)]
    Sdk(#[from] sos_net::sdk::Error),

    /// Error generated by the networking library.
    #[error(transparent)]
    Net(#[from] sos_net::Error),

    /// Error generated by the account extras library.
    #[error(transparent)]
    Extras(#[from] sos_net::extras::Error),

    /// Error generated parsing a URL.
    #[error(transparent)]
    UrlParse(#[from] sos_net::sdk::url::ParseError),

    /// Error generated by the command line argument parser.
    #[error(transparent)]
    Clap(#[from] clap::Error),

    /// Error generated converting from UTF8.
    #[error(transparent)]
    Utf8Str(#[from] std::str::Utf8Error),

    /// Error generated converting from UTF8.
    #[error(transparent)]
    Utf8String(#[from] std::string::FromUtf8Error),

    /// Error generated by the readline library.
    #[error(transparent)]
    Readline(#[from] rustyline::error::ReadlineError),

    /// Error parsing shell words.
    #[error(transparent)]
    ShellWords(#[from] shell_words::ParseError),

    /// Error parsing as boolean.
    #[error(transparent)]
    Bool(#[from] std::str::ParseBoolError),

    /// Errors generated by the vCard library.
    #[error(transparent)]
    Vcard(#[from] vcard4::Error),

    /// Errors generated by the clipboard library.
    #[error(transparent)]
    Clipboard(#[from] arboard::Error),

    /// Error generated converting hexadecimal.
    #[error(transparent)]
    Hex(#[from] sos_net::sdk::hex::FromHexError),

    /// Error generated by the CSV library.
    #[error(transparent)]
    Csv(#[from] csv_async::Error),

    /// Error generated by the Ctrl+C library.
    #[error(transparent)]
    Ctrlc(#[from] ctrlc::Error),

    /// Error generated by the TOML library.
    #[error(transparent)]
    TomlSer(#[from] toml::ser::Error),
}

impl Error {
    /// Determine if this error was an interruption error.
    pub fn is_interrupted(&self) -> bool {
        matches!(
            self,
            Error::Readline(rustyline::error::ReadlineError::Interrupted)
        )
    }
}
