#[cfg(not(target_arch = "wasm32"))]
mod test_utils;

//#[cfg(not(target_arch = "wasm32"))]
//mod account_manager;

//#[cfg(not(target_arch = "wasm32"))]
//mod archive_export_restore;

#[cfg(not(target_arch = "wasm32"))]
mod audit_trail;

#[cfg(not(target_arch = "wasm32"))]
mod change_password;

#[cfg(all(not(target_arch = "wasm32"), not(target_os = "windows")))]
mod command_line;

#[cfg(not(target_arch = "wasm32"))]
mod external_files;

#[cfg(not(target_arch = "wasm32"))]
mod local;

#[cfg(not(target_arch = "wasm32"))]
mod local_provider;

#[cfg(not(target_arch = "wasm32"))]
mod rpc;

#[cfg(not(target_arch = "wasm32"))]
mod security_report;

#[cfg(not(target_arch = "wasm32"))]
mod simple_session;

#[cfg(not(target_arch = "wasm32"))]
mod sync;

#[cfg(feature = "mem-fs")]
mod memory_vfs;
