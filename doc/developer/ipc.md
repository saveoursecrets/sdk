# IPC

This document describes the tools available to debug and inspect inter-process communication.

***Warn: if you use the `--release` flag or an actual installed release build (eg: `sos`) this would use the directory for production data.***

## Browser Extensions

To test browser extensions communicating with the IPC service without starting the GUI app you should use the socket name for the GUI:

```
cargo run -p sos -- tool ipc server --socket com.saveoursecrets.gui.sock
```

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

Note that you must be at the root of the repository so the executable is found.

## Logs

To see the log messages for the native bridge you can tail the standard logs, for example on MacOS (replace `YYYY-MM-DD` with the today):

```
tail -f ~/Library/Application\ Support/SaveOurSecrets/debug/logs/saveoursecrets.log.YYYY-MM-DD
```

