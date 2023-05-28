//! Virtual file system to support transparent file system
//! access in webassembly.

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
