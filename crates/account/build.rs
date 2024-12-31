use rustc_version::{version_meta, Channel};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(CHANNEL_NIGHTLY)");
    println!("cargo::rustc-check-cfg=cfg(NOT_CI)");

    // Set cfg flags depending on release channel
    let channel = match version_meta().unwrap().channel {
        Channel::Stable => "CHANNEL_STABLE",
        Channel::Beta => "CHANNEL_BETA",
        Channel::Nightly => "CHANNEL_NIGHTLY",
        Channel::Dev => "CHANNEL_DEV",
    };
    println!("cargo:rustc-cfg={}", channel);
    if option_env!("CI").is_some() {
        println!("cargo:rustc-cfg={}", "CI")
    } else {
        println!("cargo:rustc-cfg={}", "NOT_CI")
    }
}
