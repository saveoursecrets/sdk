// mod app_info;
// mod list_accounts;
// mod local_sync;
mod memory_server;
mod native_bridge_chunks;
// mod native_bridge_list_accounts;
mod native_bridge_probe;

pub use sos_test_utils as test_utils;

pub fn native_bridge_cmd() -> (&'static str, Vec<&'static str>) {
    let command = "cargo";
    let arguments = vec![
        "run",
        "-q",
        "--bin",
        "test-native-bridge",
        "--",
        "sos-test-native-bridge", // mock extension name
    ];
    (command, arguments)
}
