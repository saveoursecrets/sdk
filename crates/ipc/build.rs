extern crate prost_build;
use rustc_version::{version_meta, Channel};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(CHANNEL_NIGHTLY)");

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

    prost_build::compile_protos(&["src/protobuf/protocol.proto"], &["src"])
        .unwrap();
}
