use rustc_version::{version_meta, Channel};

extern crate prost_build;

fn main() {
    // Set cfg flags depending on release channel
    let channel = match version_meta().unwrap().channel {
        Channel::Stable => "CHANNEL_STABLE",
        Channel::Beta => "CHANNEL_BETA",
        Channel::Nightly => "CHANNEL_NIGHTLY",
        Channel::Dev => "CHANNEL_DEV",
    };
    println!("cargo:rustc-cfg={}", channel);

    prost_build::compile_protos(
        &[
            "src/protocol/common.proto",
            "src/protocol/diff.proto",
            "src/protocol/patch.proto",
            "src/protocol/scan.proto",
            "src/protocol/sync.proto",
        ],
        &["src/protocol"],
    )
    .unwrap();
}
