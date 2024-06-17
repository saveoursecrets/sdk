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
            "src/protocol/protobuf/common.proto",
            "src/protocol/protobuf/diff.proto",
            "src/protocol/protobuf/files.proto",
            "src/protocol/protobuf/notifications.proto",
            "src/protocol/protobuf/patch.proto",
            "src/protocol/protobuf/scan.proto",
            "src/protocol/protobuf/sync.proto",
        ],
        &["src/protocol"],
    )
    .unwrap();
}
