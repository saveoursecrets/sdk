#[cfg(not(target_arch = "wasm32"))]
mod abort_delete;

#[cfg(not(target_arch = "wasm32"))]
mod abort_move;

#[cfg(not(target_arch = "wasm32"))]
mod attachments;

#[cfg(not(target_arch = "wasm32"))]
mod late_upload;

#[cfg(not(target_arch = "wasm32"))]
mod multi_server;

#[cfg(not(target_arch = "wasm32"))]
mod offline_multi;

#[cfg(not(target_arch = "wasm32"))]
mod servers_changed;

#[cfg(not(target_arch = "wasm32"))]
mod single_server;

#[cfg(not(target_arch = "wasm32"))]
mod sync_transfers;

#[cfg(not(target_arch = "wasm32"))]
pub use sos_test_utils as test_utils;
