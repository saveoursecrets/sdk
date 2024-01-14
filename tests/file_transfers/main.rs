#[cfg(not(target_arch = "wasm32"))]
mod delete_file;

#[cfg(not(target_arch = "wasm32"))]
mod download_file;

#[cfg(not(target_arch = "wasm32"))]
mod move_file;

#[cfg(not(target_arch = "wasm32"))]
mod update_file;

#[cfg(not(target_arch = "wasm32"))]
mod upload_file;

#[cfg(not(target_arch = "wasm32"))]
pub use sos_test_utils as test_utils;
