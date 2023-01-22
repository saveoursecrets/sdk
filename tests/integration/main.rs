#[cfg(not(target_arch = "wasm32"))]
mod test_utils;

#[cfg(not(target_arch = "wasm32"))]
mod archive_export_restore;

#[cfg(not(target_arch = "wasm32"))]
mod auth_session_negotiate;

#[cfg(not(target_arch = "wasm32"))]
mod change_password;
#[cfg(not(target_arch = "wasm32"))]
mod check_integrity;

#[cfg(not(target_arch = "wasm32"))]
mod compact_force_pull;

#[cfg(not(target_arch = "wasm32"))]
mod handle_change;

#[cfg(not(target_arch = "wasm32"))]
mod local_provider;

#[cfg(not(target_arch = "wasm32"))]
mod patch_conflict_resolve;
#[cfg(not(target_arch = "wasm32"))]
mod simple_session;
