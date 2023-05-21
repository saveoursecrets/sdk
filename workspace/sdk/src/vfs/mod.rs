//! Virtual file system to support transparent file system
//! access in webassembly.

#[cfg(target_arch = "wasm32")]
mod memory;

#[cfg(not(target_arch = "wasm32"))]
mod os;

#[cfg(target_arch = "wasm32")]
pub use memory::*;

#[cfg(not(target_arch = "wasm32"))]
pub use os::*;
