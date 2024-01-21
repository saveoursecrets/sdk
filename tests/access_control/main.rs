#[cfg(not(target_arch = "wasm32"))]
mod allow;

#[cfg(not(target_arch = "wasm32"))]
mod deny;

#[cfg(not(target_arch = "wasm32"))]
pub use sos_test_utils as test_utils;
