#[cfg(not(target_arch = "wasm32"))]
mod event_log;

#[cfg(not(target_arch = "wasm32"))]
mod diff_merge;

#[cfg(not(target_arch = "wasm32"))]
mod local_account;

#[cfg(not(target_arch = "wasm32"))]
mod network_account;

#[cfg(not(target_arch = "wasm32"))]
pub use sos_test_utils as test_utils;
