//! Log tracing output to disc.
use crate::Result;
use rev_buf_reader::RevBufReader;
use sos_core::{Paths, UtcDateTime};
use std::{
    fs::File,
    io::BufRead,
    path::{Path, PathBuf},
};
use time::OffsetDateTime;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const LOG_FILE_NAME: &str = "saveoursecrets.log";
const DEFAULT_LOG_LEVEL: &str =
    "sos=info,sos_sdk=debug,sos_net=debug,sos_bindings=debug";

/// State of the log files on disc.
pub struct LogFileStatus {
    /// Path to the current log file.
    pub current: PathBuf,
    /// Size of the current log file.
    pub current_size: u64,
    /// List of all log files.
    pub log_files: Vec<PathBuf>,
    /// Total size of all log files.
    pub total_size: u64,
}

/// Application logger.
///
/// When `debug_assertions` are enabled tracing output is written
/// to stdout and to disc; for release builds tracing is just written
/// to disc.
pub struct Logger {
    logs_dir: PathBuf,
    name: String,
}

impl Default for Logger {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Logger {
    /// Create a new logger using default paths.
    ///
    /// # Panics
    ///
    /// If the default data directory could not be determined.
    pub fn new(name: Option<String>) -> Self {
        Self::new_paths(Paths::new_global(Paths::data_dir().unwrap()), name)
    }

    /// Create a new logger with the given paths.
    pub fn new_paths(paths: Paths, name: Option<String>) -> Self {
        let logs_dir = paths.logs_dir().to_owned();
        Self {
            logs_dir,
            name: name.unwrap_or(LOG_FILE_NAME.to_string()),
        }
    }

    /// Create a new logger with the given directory and file name.
    pub fn new_dir(logs_dir: PathBuf, name: String) -> Self {
        Self { logs_dir, name }
    }

    /// Initialize the tracing subscriber.
    #[cfg(debug_assertions)]
    pub fn init_subscriber(
        &self,
        default_log_level: Option<String>,
    ) -> Result<()> {
        let logs_dir = &self.logs_dir;

        let logfile =
            RollingFileAppender::new(Rotation::DAILY, logs_dir, &self.name);
        let default_log_level =
            default_log_level.unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_owned());
        let env_layer = tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or(default_log_level),
        );

        let file_layer = tracing_subscriber::fmt::layer()
            .with_file(false)
            .with_line_number(false)
            .with_ansi(false)
            .json()
            .with_writer(logfile);

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_file(false)
            .with_line_number(false)
            .with_writer(std::io::stderr)
            .with_target(false);

        // NOTE: drop the error if already set so hot reload
        // NOTE: does not panic in the GUI
        let _ = tracing_subscriber::registry()
            .with(env_layer)
            .with(fmt_layer)
            .with(file_layer)
            .try_init();

        Ok(())
    }

    /// Initialize a subscriber that writes to a file.
    pub fn init_file_subscriber(
        &self,
        default_log_level: Option<String>,
    ) -> Result<()> {
        let logfile = RollingFileAppender::new(
            Rotation::DAILY,
            &self.logs_dir,
            &self.name,
        );
        let default_log_level =
            default_log_level.unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_owned());
        let env_layer = tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or(default_log_level),
        );

        let file_layer = tracing_subscriber::fmt::layer()
            .with_file(false)
            .with_line_number(false)
            .with_ansi(false)
            .json()
            .with_writer(logfile);

        // NOTE: drop the error if already set so hot reload
        // NOTE: does not panic in the GUI
        let _ = tracing_subscriber::registry()
            .with(env_layer)
            .with(file_layer)
            .try_init();

        Ok(())
    }

    /// Initialize the tracing subscriber.
    #[cfg(not(debug_assertions))]
    pub fn init_subscriber(
        &self,
        default_log_level: Option<String>,
    ) -> Result<()> {
        self.init_file_subscriber(default_log_level)
    }

    /// Log file status.
    pub fn status(&self) -> Result<LogFileStatus> {
        let current = self.current_log_file()?;
        let current_size = std::fs::metadata(&current)?.len();
        let log_files = self.log_file_paths()?;
        let mut total_size = 0;
        for path in &log_files {
            total_size += std::fs::metadata(path)?.len();
        }
        Ok(LogFileStatus {
            current,
            current_size,
            log_files,
            total_size,
        })
    }

    /// Load the tail of log records for the current file.
    pub fn tail(&self, num_lines: Option<usize>) -> Result<Vec<String>> {
        self.tail_file(num_lines, self.current_log_file()?)
    }

    /// Load the tail of log records for a file.
    pub fn tail_file(
        &self,
        num_lines: Option<usize>,
        path: impl AsRef<Path>,
    ) -> Result<Vec<String>> {
        let num_lines = num_lines.unwrap_or(100);
        let file = File::open(path.as_ref())?;
        let buf = RevBufReader::new(file);
        let logs: Vec<String> =
            buf.lines().take(num_lines).filter_map(|l| l.ok()).collect();
        Ok(logs)
    }

    /// Delete all log files except the current log file.
    pub fn delete_logs(&self) -> Result<()> {
        let current = self.current_log_file()?;
        let log_files = self.log_file_paths()?;
        for path in log_files {
            if path != current {
                std::fs::remove_file(path)?;
            }
        }
        // Workaround for set_len(0) failing with "Access Denied" on Windows
        // SEE: https://github.com/rust-lang/rust/issues/105437
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&current);
        Ok(())
    }

    /// Get all the log files in the logs directory.
    fn log_file_paths(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&self.logs_dir)? {
            let entry = entry?;
            let path = entry.path();
            if let Some(name) = path.file_name() {
                if name.to_string_lossy().starts_with(&self.name) {
                    files.push(path);
                }
            }
        }
        Ok(files)
    }

    /// Log file for today.
    fn current_log_file(&self) -> Result<PathBuf> {
        let now: UtcDateTime = OffsetDateTime::now_utc().into();
        let file = self.logs_dir.join(format!(
            "{}.{}",
            self.name,
            now.format_simple_date()?
        ));
        Ok(file)
    }
}
