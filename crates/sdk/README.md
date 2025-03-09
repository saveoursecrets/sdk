Software development kit for a distributed, local-first, encrypted database that can be used to build password managers, cryptocurrency wallets or other applications that require storing secrets securely.

See the [Save Our Secrets](https://saveoursecrets.com) website for the app, more documentation and information.

## Backends

There are two storage backends, a [file system backend](https://docs.rs/sos-filesystem/latest/sos_filesystem/) which uses append-only files for event logs and a newer SQLite [database backend](https://docs.rs/sos-database/latest/sos_database/). The [sos-backend](https://docs.rs/sos-backend/latest/sos_backend/) crate is an abstraction for multiple storage backends and should be used to create a backend target.

The file system backend is now considered legacy and may be removed in a future version.

## Crates

A higher-level account management API is described in [sos_account::Account](https://docs.rs/sos-account/latest/sos_account/trait.Account.html) which is implemented by [sos_account::LocalAccount](https://docs.rs/sos-account/latest/sos_account/struct.LocalAccount.html). For a network aware account with sync capability use [sos_net::NetworkAccount](https://docs.rs/sos-net/latest/sos_net/struct.NetworkAccount.html).

For lower-level access use the types in the [sos-vault](https://docs.rs/sos-vault/latest/sos_vault/) crate.

This crate exports a prelude of common types for low-level access but we encourage using the appropriate crate directly.

| Crate                                                                                                         | Description     |
|:------------------                                                                                            |:------------|
| [sos-account](https://docs.rs/sos-account/latest/sos_account/)                                                | Local account management |
| [sos-archive](https://docs.rs/sos-archive/latest/sos_archive/)                                                | ZIP archive support |
| [sos-artifact](https://docs.rs/sos-artifact/latest/sos_artifact/)                                             | Release artifact types |
| [sos-audit](https://docs.rs/sos-audit/latest/sos_audit/)                                                      | Audit log types and traits |
| [sos-backend](https://docs.rs/sos-backend/latest/sos_backend/)                                                | Abstraction for multiple storage backends |
| [sos-cli-helpers](https://docs.rs/sos-cli-helpers/latest/sos_cli_helpers/)                                    | Helper functions for the CLI tools |
| [sos-core](https://docs.rs/sos-core/latest/sos_core/)                                                         | Core types and traits; cryptography functions, commit trees and event definitions. |
| [sos-database](https://docs.rs/sos-database/latest/sos_database/)                                             | SQLite database backend |
| [sos-database-upgrader](https://docs.rs/sos-database-upgrader/latest/sos_database_upgrader/)                  | Upgrade filesystem backend to database backend |
| [sos-external-files](https://docs.rs/sos-external-files/latest/sos_external_files/)                           | Helper functions for managing external encrypted file blobs |
| [sos-filesystem](https://docs.rs/sos-filesystem/latest/sos_filesystem/)                                       | Legacy filesystem backend |
| [sos-integrity](https://docs.rs/sos-integrity/latest/sos_integrity/)                                          | Vault, event log and external file blob integrity checks |
| [sos-ipc](https://docs.rs/sos-ipc/latest/sos_ipc/)                                                            | IPC service and executable for the companion browser extension |
| [sos-login](https://docs.rs/sos-login/latest/sos_login/)                                                      | Login and identity folder for authentication |
| [sos-logs](https://docs.rs/sos-logs/latest/sos_logs/)                                                         | Standard logging facility |
| [sos-migrate](https://docs.rs/sos-migrate/latest/sos_migrate/)                                                | Import from and export to other apps (unencrypted data) |
| [sos-net](https://docs.rs/sos-net/latest/sos_net/)                                                            | Network-aware accounts with sync capability |
| [sos-password](https://docs.rs/sos-password/latest/sos_password/)                                             | Strong password generation |
| [sos-platform-authenticator](https://docs.rs/sos-platform-authenticator/latest/sos_platform_authenticator/)   | Native platform authenticator and keyring integration |
| [sos-preferences](https://docs.rs/sos-preferences/latest/sos_preferences/)                                    | Types and traits for global and account user preferences |
| [sos-protocol](https://docs.rs/sos-protocol/latest/sos_protocol/)                                             | Network client and protocol |
| [sos-reducers](https://docs.rs/sos-reducers/latest/sos_reducers/)                                             | Reduce event logs into compact representations |
| [sos-remote-sync](https://docs.rs/sos-remote-sync/latest/sos_remote_sync/)                                    | Remote sync and auto merge implementations |
| [sos-search](https://docs.rs/sos-search/latest/sos_search/)                                                   | In-memory search index |
| [sos-security-report](https://docs.rs/sos-security-report/latest/sos_security_report/)                        | Generate security reports for accounts |
| [sos-server](https://docs.rs/sos-server/latest/sos_server/)                                                   | Self-hosted server library and CLI |
| [sos-signer](https://docs.rs/sos-signer/latest/sos_signer/)                                                   | Cryptographic signatures |
| [sos](https://docs.rs/sos/latest/sos/)                                                                        | Client command line interface and shell REPL |
| [sos-client-storage](https://docs.rs/sos-client-storage/latest/sos_client_storage/)                           | Storage implementation for clients |
| [sos-server-storage](https://docs.rs/sos-server-storage/latest/sos_server_storage/)                           | Storage implementation for servers |
| [sos-sync](https://docs.rs/sos-sync/latest/sos_sync/)                                                         | Sync protocol types and traits |
| [sos-system-messages](https://docs.rs/sos-system-messages/latest/sos_system_messages/)                        | Persistent, application system messages |
| [sos-vault](https://docs.rs/sos-vault/latest/sos_vault/)                                                      | Secure secret storage |
| [sos-vfs](https://docs.rs/sos-vfs/latest/sos_vfs/)                                                            | Virtual File System for WASM support |

## API

The public API is not considered stable and may be changed at any time prior to a `1.0.0` release.

## MSRV

We track the latest stable Rust toolchain (currently `1.85.0`) so we can use new features as they are stabilized the code may compile on older versions.

## License

The client code is either MIT or Apache-2.0, you choose; the server is released under the AGPL-3.0 license.
