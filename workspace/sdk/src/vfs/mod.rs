//! Virtual file system designed to match the `tokio::fs` module.
//!
//! Using the memory VFS allows webassembly to support
//! asynchronous file system access using a familiar API.
//!
//! The default operating system VFS re-exports the
//! `tokio::fs` module.
//!
//! The memory file system is enabled by default for
//! `wasm32-unknown-unknown` or if the `mem-fs` feature
//! is enabled.
//!
//! # Memory VFS Caveats
//!
//! Relative paths are resolved from the root of the file system.
//!
//! Avoid using the `PathBuf` functions `exists()`, `metadata()`,
//! `is_dir()`, `is_file()` etc as they will be incorrect when
//! using a virtual file system. Instead use the `vfs::metadata()` and
//! `vfs::try_exists()` asynchronous functions.
//!
//! The `SystemTime` type is not available on `wasm32-unknown-unknwown`
//! so `Metadata` does not support `created()`, `accessed()`
//! and `modified()` for that target.
//!
//! # Memory VFS Unsupported
//!
//! This functionality is not supported yet but we hope to
//! implement in the future.
//!
//! The `readonly` flag on permissions is not supported yet.
//!
//! Created, accessed and modified times are not set
//! yet for non-webassembly targets that support `SystemTime`.
//!
//! Symbolic links are not supported yet which means the `hard_link()`,
//! `symlink()`, `symlink_metadata()`, `symlink_file()` and
//! `symlink_dir()` functions are not available.
//!

#[cfg(any(
    feature = "mem-fs",
    all(target_arch = "wasm32", target_os = "unknown")
))]
mod memory;

#[cfg(all(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    not(feature = "mem-fs")
))]
mod os;

#[cfg(any(
    feature = "mem-fs",
    all(target_arch = "wasm32", target_os = "unknown")
))]
pub use memory::*;

#[cfg(all(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    not(feature = "mem-fs")
))]
pub use os::*;
