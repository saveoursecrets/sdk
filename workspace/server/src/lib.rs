mod assets;
mod audit_log;
mod authenticate;
mod backend;
mod config;
mod error;
mod file_locks;
mod headers;
mod server;

pub type Result<T> = std::result::Result<T, error::Error>;

pub use audit_log::LogFile as AuditLogFile;
pub use authenticate::Authentication;
pub use backend::{Backend, FileSystemBackend};
pub use config::ServerConfig;
pub use error::Error;
pub use file_locks::LockFiles;
pub use server::{Server, State};
