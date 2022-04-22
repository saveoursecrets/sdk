mod assets;
mod audit;
mod authenticate;
mod backend;
mod config;
mod error;
mod server;

pub type Result<T> = std::result::Result<T, error::Error>;

pub use audit::LogFile as AuditLogFile;
pub use authenticate::Authentication;
pub use backend::{Backend, FileSystemBackend};
pub use config::ServerConfig;
pub use error::Error;
pub use server::{Server, State};
