//! ZIP archive reader and writer for account backup archives.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
mod reader;
mod writer;

pub use error::Error;
pub use reader::Reader as ZipReader;
pub use writer::Writer as ZipWriter;

/// Manifest file for archives.
pub const ARCHIVE_MANIFEST: &str = "sos-manifest.json";

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Returns a relative path without reserved names,
/// redundant separators, ".", or "..".
pub fn sanitize_file_path(path: &str) -> std::path::PathBuf {
    // Replaces backwards slashes
    path.replace('\\', "/")
        // Sanitizes each component
        .split('/')
        .map(sanitize_filename::sanitize)
        .collect()
}
