# Save Our Secrets Library

> Save our Secrets (SOS) is a cross-platform, distributed, encrypted database with a focus on security, integrity and redundancy. It can be used to store private secrets such as account passwords, notes, certificates and encryption keys.

This repository contains the core library code and several command line interface (CLI) tools.

* [sandbox](/sandbox) Configuration and storage location for local testing.
* [workspace](/workspace) Libraries and command line interfaces.
    * [audit](/workspace/audit) The `sos-audit` tool for reading and monitoring audit logs.
    * [check](/workspace/check) The `sos-check` tool for verifying file integrity and inspecting files.
    * [client](/workspace/client) Client library and the `sos-client` terminal read-eval-print-loop (REPL) tool.
    * [core](/workspace/core) Core library including types and traits common to the client and server implementations.
    * [readline](/workspace/readline) Utility functions for reading from stdin, used by the terminal REPL client.
    * [server](/workspace/server) Server command line interface.

For webassembly bindings see the [browser][] repository.

## Design

A vault is a collection of encrypted secrets and their associated meta data. Vaults can be represented as both an append-only log file for synchronization and a compact binary file for archiving and portability. Bi-directional conversion between the append-only log and compact binary file is straightforward; the library provides methods to *reduce* the append-only log to a vault and *split* a vault into it's header and a collection of events that can be appended to a log.

Synchronization between nodes is done using the append-only log file (which we refer to as a write-ahead log or WAL); a Merkle tree is computed for each log file using the hash of the data for each record. By comparing Merkle proofs we can easily determine which tree is ahead or whether the trees have diverged; much in the same way that [git][] synchronizes source code.

Secrets are *always encrypted on the client* using a random nonce and one of the supported algorithms, either XChaCha20Poly1305 or AES-GCM 256. The default algorithm is XChaCha20Poly1305 for it's extended 24 byte nonce and because it does not required special AES instructions on the CPU to be implemented safely.

## Setup

Tasks are run using `cargo make`, install it with:

```
cargo install cargo-make
```

The minimum supported Rust version (MSRV) is 1.62; to view the API documentation for all crates run `cargo make docs`.

## Test

* Run all tests: `cargo make test`
* Unit tests: `cargo make unit`
* Integration tests: `cargo make integration`

### Coverage

For code coverage install the `llvm-tools-preview` and `grcov`:

```
rustup component add llvm-tools-preview && cargo install grcov
```

And to generate the HTML from the `lcov.info` file install [lcov][]; then you can run:

```
cargo make coverage
```

The HTML coverage report is at `target/coverage/index.html`.

## Server

### Certificates

The server requires TLS so a certificate and key file must be configured.

For local development use [mkcert][] in the sandbox directory, first install the executable and then create the certificate authority:

```
mkcert -install
```

Afterwards create certificates for local servers in the sandbox directory:

```
cargo make dev-certs
```

### Web GUI

The server bundles a web-based GUI from the browser webapp code so to run the server CLI tool you must have the [browser][] repository as a sibling folder of this repository and then you can build the public folder containing the bundled assets:

```
cargo make browser-gui
```

Now you can start a development version of the server using the [sandbox configuration](/sandbox/config.toml):

```
cargo make dev-server
```

Accounts and vaults will be created in the sandbox directory.

### Release

To create a release build with the bundled GUI assets run:

```
cargo make server-release
```

[git]: https://git-scm.com/
[lcov]: https://github.com/linux-test-project/lcov
[grcov]: https://github.com/mozilla/grcov
[mkcert]: https://github.com/FiloSottile/mkcert
[browser]: https://github.com/saveoursecrets/browser
