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

    // utoipa_config::Config::new()
    // .alias_for("MyType", "bool")
    // .alias_for("MyInt", "Option<i32>")
    // .alias_for("MyValue", "str")
    // .alias_for("MyDateTime", "String")
    // .alias_for("EntryAlias", "Entry<i32>")
    // .alias_for("EntryString", "Entry<String>")
    // .write_to_file()
}
