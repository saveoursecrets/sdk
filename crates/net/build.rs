extern crate prost_build;

fn main() {
    std::env::set_var(
        "PROTOC",
        protoc_bin_vendored::protoc_bin_path().unwrap(),
    );

    prost_build::compile_protos(
        &[
            "src/protocol/protobuf/common.proto",
            "src/protocol/protobuf/diff.proto",
            "src/protocol/protobuf/files.proto",
            "src/protocol/protobuf/notifications.proto",
            "src/protocol/protobuf/patch.proto",
            "src/protocol/protobuf/relay.proto",
            "src/protocol/protobuf/scan.proto",
            "src/protocol/protobuf/sync.proto",
        ],
        &["src/protocol"],
    )
    .unwrap();
}
