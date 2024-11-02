# IPC

This document describes the tools available to debug and inspect inter-process communication.

***Warn: if you use the `--release` flag or an actual installed release build (eg: `sos`) this would use the directory for production data.***

## Server

To start a standalone IPC service that uses local accounts:

```
cargo run -p sos -- tool ipc server
```

Note: that this uses the inferred data directory for the accounts so you can use `SOS_DATA_DIR` if you need to use different accounts.

## Client

Then you can send either directly as protobuf via IPC, for example:

```
cargo run -p sos -- tool ipc send list-accounts
```

Or as JSON via the native bridge executable by specifying the command and arguments:

```
cargo run -p sos -- tool ipc send -c target/debug/sos -a tool -a ipc -a bridge list-accounts
```
