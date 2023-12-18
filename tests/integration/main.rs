#[cfg(not(target_arch = "wasm32"))]
mod event_log;

#[cfg(all(not(target_arch = "wasm32"), not(target_os = "windows")))]
mod command_line;

#[cfg(not(target_arch = "wasm32"))]
mod diff_merge;

#[cfg(not(target_arch = "wasm32"))]
mod local_account;

//#[cfg(not(target_arch = "wasm32"))]
//mod network_account;

#[cfg(not(target_arch = "wasm32"))]
mod rpc;

#[cfg(not(target_arch = "wasm32"))]
pub use sos_test_utils as test_utils;
