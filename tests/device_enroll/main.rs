#![allow(dead_code)]

#[cfg(not(target_arch = "wasm32"))]
mod enroll;

#[cfg(not(target_arch = "wasm32"))]
pub use sos_test_utils as test_utils;
