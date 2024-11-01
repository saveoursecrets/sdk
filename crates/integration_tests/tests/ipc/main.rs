mod authenticate_success;
mod authenticate_timeout;
mod list_accounts;

pub use sos_test_utils as test_utils;

#[cfg(target_os = "macos")]
pub(crate) fn remove_socket_file(socket_name: &str) {
    let socket_path =
        std::path::PathBuf::from(format!("/tmp/{}", socket_name));
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }
}
