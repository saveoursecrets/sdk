# Save Our Secrets Library

> A distributed, encrypted database with a focus on security, integrity and redundancy.

Used to store private secrets such as account passwords, notes, certificates and encryption keys.

## Server

The server requires TLS so a certificate and key file must be configured.

For local development use [mkcert][] in the sandbox directory:

```
mkcert -install
cd sandbox && mkcert -key-file key.pem -cert-file cert.pem localhost 127.0.0.1 ::1
```

Now you can start a development version of the server:

```
cd workspace/server
cargo run -- -c ../../sandbox/config.toml
```

Accounts and vaults will be created in the sandbox directory.

### Release

The server bundles a web-based GUI from the browser webapp code so to make a release build of the server CLI tool you must have the [browser][] repository as a sibling folder of this repository and then run:

```
make server-release
```

[mkcert]: https://github.com/FiloSottile/mkcert

[browser]: https://github.com/saveoursecrets/browser
