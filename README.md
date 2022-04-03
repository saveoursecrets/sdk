# Secret Storage

Stores our secrets such as passwords, GPG keys and SSH keys using 256 bit AES-GCM encryption with support for recovery using multi-party ECDSA signatures.

* `android`: Sources for the Android build.
* `browser`: React web application for the browser.
* `ios`: Sources for the iOS build.
* `lib`: Dart source files.
* `linux`: Sources for the Linux build.
* `macos`: Sources for the MacOS build.
* `native`: Sources and generated files for the Rust/Flutter bindings.
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

## Browser

To develop with the webassembly bindings in the browser application link the webassembly module:

```
(cd workspace/wasm/pkg && yarn link)
(cd browser && yarn link sos-wasm)
```

## Command Line

To create a new vault with a randomly generated diceware passphrase:

```
sos3 new vault /path/to/folder
```

To create a new vault from an existing passphrase write it to stdin:

```
cat secret.txt | sos3 new vault /path/to/folder
```
