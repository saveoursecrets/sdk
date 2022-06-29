# Secret Storage

A distributed, encrypted database with a focus on security, integrity and redundancy.

Used to store private secrets such as account passwords, notes, certificates and encryption keys.

## Repository

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

## Server

The server requires TLS so a certificate and key file must be configured.

For local development use [mkcert][]:

```
mkcert -install
mkcert -key-file key.pem -cert-file cert.pem localhost 127.0.0.1 ::1
```

Then place the files next to the server configuration and update the `[tls]` section in the server configuration:

```toml
[tls]
cert = "cert.pem"
key = "key.pem"
```

Now you can start a development version of the server:

```
cd workspace/server
cargo run -- -c /path/to/config.toml
```

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

[mkcert]: https://github.com/FiloSottile/mkcert
