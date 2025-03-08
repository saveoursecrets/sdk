Software development kit for a distributed, encrypted database that can be used to build password managers, cryptocurrency wallets or other applications that require storing secrets securely.

See the [Save Our Secrets](https://saveoursecrets.com) website for the app, more documentation and information.

A higher-level account management API is described in [sos_account::Account](https://docs.rs/sos-account/latest/sos_account/trait.Account.html) which is implemented by [sos_account::LocalAccount](https://docs.rs/sos-account/latest/sos_account/struct.LocalAccount.html). For a network aware account with sync capability use [sos_net::NetworkAccount](https://docs.rs/sos-net/latest/sos_net/struct.NetworkAccount.html).

For lower-level access use the types in the [sos-vault](https://docs.rs/sos-vault/latest/sos_vault/) crate.

## Features

* `contacts` Manage account contacts.
* `files` Store external encrypted files.

## Backends

There are two storage backends, a [file system backend](https://docs.rs/sos-filesystem/latest/sos_filesystem/) which uses append-only files for event logs and a newer SQLite [database backend](https://docs.rs/sos-database/latest/sos_database/). The [sos-backend](https://docs.rs/sos-backend/latest/sos_backend/) crate is an abstraction for multiple storage backends and should be used to create a backend target.

The file system backend is now considered legacy and may be removed in a future version.

## Crates

| Crate                                                                       | Description     |
|:------------------                                                          |:------------|
| [sos-account](https://docs.rs/sos-account/latest/sos_account/)              | Local account management |

## API

The public API is not considered stable and may be changed at any time prior to a `1.0.0` release.

## MSRV

We track the latest stable Rust toolchain (currently `1.85.0`) so we can use new features as they are stabilized the code may compile on older versions.
