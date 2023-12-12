#![allow(dead_code)]

#[cfg(not(target_arch = "wasm32"))]
mod local_account;

#[cfg(not(target_arch = "wasm32"))]
mod test_utils;
