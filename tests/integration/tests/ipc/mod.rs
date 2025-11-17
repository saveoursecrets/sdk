mod extension_helper_chunks;
mod extension_helper_info;
mod extension_helper_list_accounts;
mod extension_helper_probe;
mod memory_server;

pub fn extension_helper_cmd(data_dir: &str) -> (&'static str, Vec<&str>) {
    let command = "cargo";
    let arguments = vec![
        "run",
        "-q",
        "--bin",
        "test-extension-helper",
        "--",
        "sos-test-extension-helper", // mock extension name
        data_dir,                    // data directory for isolated tests
    ];
    (command, arguments)
}
