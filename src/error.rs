use sos_core::{vault::secret::SecretRef, vcard4};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
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

    #[error(
        r#"folder "{0}" not found, run "folders" to load the folder list"#
    )]
    VaultNotAvailable(SecretRef),

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
    Core(#[from] sos_core::Error),

    #[error(transparent)]
    Node(#[from] sos_node::Error),

    #[error(transparent)]
    NodeClient(#[from] sos_node::client::Error),

    #[error(transparent)]
    UrlParse(#[from] sos_core::url::ParseError),

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
    Server(#[from] sos_node::server::Error),

    #[error(transparent)]
    Peer(#[from] sos_node::peer::Error),
}
