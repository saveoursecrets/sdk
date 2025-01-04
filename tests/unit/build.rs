fn main() {
    println!("cargo::rustc-check-cfg=cfg(NOT_CI)");
    if option_env!("CI").is_some() {
        println!("cargo:rustc-cfg={}", "CI")
    } else {
        println!("cargo:rustc-cfg={}", "NOT_CI")
    }
}
