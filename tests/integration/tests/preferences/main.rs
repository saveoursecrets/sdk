mod concurrent_write;
mod global_preferences;
mod local_account;
mod no_account;

pub use sos_test_utils as test_utils;
pub use test_utils::assert::assert_preferences;

pub fn test_preferences_concurrency<'a>(
    data_dir: &'a str,
    value: &'a str,
) -> (&'static str, Vec<&'a str>) {
    let command = "cargo";
    let arguments = vec![
        "run",
        "-q",
        "--bin",
        "test-preferences-concurrency",
        "--",
        value,
        data_dir, // data directory for isolated tests
    ];
    (command, arguments)
}
