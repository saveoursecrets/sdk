extern crate prost_build;

fn main() {
    unsafe {
        std::env::set_var(
            "PROTOC",
            protoc_bin_vendored::protoc_bin_path().unwrap(),
        );
    }

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
