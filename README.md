# Secret Storage

Stores our secrets such as passwords, GPG keys and SSH keys using 256 bit AES-GCM encryption with support for recovery using multi-party ECDSA signatures.

* `android`: Sources for the Android build.
* `ios`: Sources for the iOS build.
* `lib`: Dart source files.
* `linux`: Sources for the Linux build.
* `macos`: Sources for the MacOS build.
* `native`: Sources and generated files for the Rust/Flutter bindings.
* `sandbox`: Playground for the webassembly bindings.
* `test`: Dart test files.
* `web`: Sources for the Web build.
* `whitepaper`: LaTeX sources for the protocol whitepaper.
* `windows`: Sources for the Windows build.
* `workspace`: Rust source files.

## Webassembly

To compile the webassembly bindings:

```
make wasm
```

## Sandbox

To develop with the webassembly bindings in the sandbox link the webassembly module:

```
(cd workspace/wasm/pkg && yarn link)
(cd sandbox && yarn link sos-wasm)
```
