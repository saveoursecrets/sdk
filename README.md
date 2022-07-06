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

The minimum supported Rust version (MSRV) is 1.62; to view the API documentation for all crates run `make docs`.

## Server

### Certificates

The server requires TLS so a certificate and key file must be configured.

For local development use [mkcert][] in the sandbox directory, first install the executable and then create the certificate authority:

```
mkcert -install
```

Afterwards create certificates for local servers in the sandbox directory:

```
make dev-certs
```

### Web GUI

The server bundles a web-based GUI from the browser webapp code so to run the server CLI tool you must have the [browser][] repository as a sibling folder of this repository and then you can build the public folder containing the bundled assets:

```
make browser-gui
```

Now you can start a development version of the server using the [sandbox configuration](/sandbox/config.toml):

```
make dev-server
```

Accounts and vaults will be created in the sandbox directory.

### Release

To create a release build with the bundled GUI assets run:

```
make server-release
```

[mkcert]: https://github.com/FiloSottile/mkcert

[browser]: https://github.com/saveoursecrets/browser
