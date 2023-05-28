//! Virtual file system to support transparent file system
//! access in webassembly.

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod memory;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod os;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use memory::*;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use os::*;
