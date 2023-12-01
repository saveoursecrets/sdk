#[cfg(not(target_arch = "wasm32"))]
mod test_utils;

#[cfg(not(target_arch = "wasm32"))]
mod audit_trail;

//#[cfg(all(not(target_arch = "wasm32"), not(target_os = "windows")))]
//mod command_line;

#[cfg(not(target_arch = "wasm32"))]
mod local_account;

#[cfg(not(target_arch = "wasm32"))]
mod rpc;

#[cfg(not(target_arch = "wasm32"))]
mod sync;
