extern crate prost_build;
use rustc_version::{version_meta, Channel};

fn main() {
    // Set cfg flags depending on release channel
    let channel = match version_meta().unwrap().channel {
        Channel::Stable => "CHANNEL_STABLE",
        Channel::Beta => "CHANNEL_BETA",
        Channel::Nightly => "CHANNEL_NIGHTLY",
        Channel::Dev => "CHANNEL_DEV",
    };
    println!("cargo:rustc-cfg={}", channel);

    std::env::set_var(
        "PROTOC",
        protoc_bin_vendored::protoc_bin_path().unwrap(),
    );

    prost_build::compile_protos(
        &[
            "src/protobuf/common.proto",
            "src/protobuf/diff.proto",
            "src/protobuf/files.proto",
            "src/protobuf/notifications.proto",
            "src/protobuf/patch.proto",
            "src/protobuf/relay.proto",
            "src/protobuf/scan.proto",
            "src/protobuf/sync.proto",
        ],
        &["src"],
    )
    .unwrap();
}
