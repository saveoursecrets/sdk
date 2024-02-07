#[cfg(not(target_arch = "wasm32"))]
mod local_account;

#[cfg(not(target_arch = "wasm32"))]
mod no_account;

#[cfg(not(target_arch = "wasm32"))]
pub use sos_test_utils as test_utils;
