# Save Our Secrets Library

> Save our Secrets (SOS) is a cross-platform, distributed, encrypted database with a focus on security, integrity and redundancy. It can be used to store private secrets such as account passwords, notes, certificates and encryption keys.

This repository contains the core library code and several command line interface (CLI) tools.

* [Layout](#repository-layout) Guide to the repository layout
* [Design](#design) Brief overview of the design
* [Development](#development) Set up a development environment
* [Getting Started](#getting-started) Getting started guide for developers 

## Repository Layout

* [sandbox](/sandbox) Configuration and storage location for local testing.
* [tests](/tests) Integration tests.
* [workspace](/workspace) Libraries and command line interfaces.
    * [audit](/workspace/audit) The `sos-audit` tool for reading and monitoring audit logs.
    * [check](/workspace/check) The `sos-check` tool for verifying file integrity and inspecting files.
    * [client](/workspace/client) The `sos-client` terminal read-eval-print-loop (REPL) tool.
    * [core](/workspace/core) Core library types and traits.
    * [node](/workspace/node) Networking library.
    * [readline](/workspace/readline) Utility functions for reading from stdin.
    * [server](/workspace/server) The `sos-server` server command line interface.

For webassembly bindings see the [browser][] repository.

## Design

A vault is a collection of encrypted secrets. Vaults can be represented as both an append-only log file for synchronization and a compact binary file for archiving and portability. Bi-directional conversion between the append-only log and compact binary file is straightforward; the library provides functions to *reduce* the append-only log to a vault and *split* a vault into it's header and a collection of events that can be appended to a log.

Synchronization between nodes is done using the append-only log file (which we refer to as a write-ahead log or WAL); a Merkle tree is computed for each log file using the hash of the data for each record. By comparing Merkle proofs we can easily determine which tree is ahead or whether the trees have diverged; much in the same way that [git][] synchronizes source code.

Secrets are *always encrypted on the client* using a random nonce and one of the supported algorithms, either XChaCha20Poly1305 or AES-GCM 256. The default algorithm is XChaCha20Poly1305 for it's extended 24 byte nonce and because it does not require AES-specific CPU instructions to be implemented safely.

### Changes

When a node wants to make changes to another node it sends a commit proof of it's current HEAD node and a patch file containing the events to apply to the remote node.

If the remote node has the same HEAD commit then the patch can be applied safely and a success response is returned to the node that made the request; when the calling node gets a success response it applies the patch to it's local copy of the append-only log.

If the remote node *contains* the HEAD commit then it will send a CONFLICT response and a proof that it contains the calling node's HEAD. The calling node can then synchronize by pulling changes from the remote node and try to apply the patch again.

If a calling node gets a CONFLICT response and no match proof but it contains the HEAD proof returned by the remote node then it can push it's local changes to the remote node and try again.

If a calling node gets a CONFLICT response and no match proof and it does not contain the HEAD proof send by the remote node then it is a *hard conflict* and will need to be resolved, see [Conflicts](#conflicts).

### Networking

For the networking layer we plan to support three different modes of operation:

* [x] `SPOT`: Single Point of Truth using a standard client/server architecture.
* [ ] `PEER`: Synchronization of nodes on a trusted LAN using mDNS for discovery.
* [ ] `VPN`: Synchronization of nodes over a WAN using the [wireguard][] VPN.

### Conflicts

Conflicts are categorised into *soft conflicts* which can be automatically resolved via synchronization and *hard conflicts* which may require user approval to be resolved.

#### Soft Conflict

Soft conflicts occur when a node tries to make changes to another node but cannot as their commit trees are out of sync but have not diverged. These sorts of conflicts can be resolved by pushing local changes or pulling remote changes to synchronize; if the synchronization is successful the calling node can try again.

#### Hard Conflict

The system is eventually consistent except in the case of two events; when a WAL is compacted to prune history or when the encryption password for a vault is changed. Either of these events will completely rewrite the append-only log and therefore the vault commit trees will have diverged. If all nodes are connected when these events occur then it is possible to synchronize automatically but if a node is offline (or an error occurs) then we have a conflict that must be resolved; we call this a *hard conflict*.

## Development

### Setup

Tasks are run using `cargo make`, install it with:

```
cargo install cargo-make
```

The minimum supported Rust version (MSRV) is 1.62; to view the API documentation for all crates run `cargo make docs`.

### Test

* Run all tests: `cargo make test`
* Unit tests: `cargo make unit`
* Integration tests: `cargo make integration`

#### Coverage

For code coverage install the `llvm-tools-preview` and `grcov`:

```
rustup component add llvm-tools-preview && cargo install grcov
```

Then you can run:

```
cargo make coverage
```

The HTML coverage report is at `target/coverage/index.html`.

### Server

#### Certificates

The server requires TLS so a certificate and key file must be configured.

For local development use [mkcert][] in the sandbox directory, first install the executable and then create the certificate authority:

```
mkcert -install
```

Afterwards create certificates for local servers in the sandbox directory:

```
cargo make dev-certs
```

#### Web GUI

The server bundles a web-based GUI from the browser webapp code so to run the server CLI tool you must have the [browser][] repository as a sibling folder of this repository and then you can build the public folder containing the bundled assets:

```
cargo make browser-gui
```

Now you can start a development version of the server using the [sandbox configuration](/sandbox/config.toml):

```
cargo make dev-server
```

Accounts and vaults will be created in the sandbox directory.

#### Release

Before making a release install the [cargo-release][] tool:

```
cargo install cargo-release
```

Perform a release dry run:

```
cargo release --workspace
```

Then to cut a new release which will publish the libraries as crates and create a new git tag for the release run:

```
cargo release --workspace -x
```

The new git tag will trigger a github workflow that will build all the artifacts across the supported platform matrix.

To skip publishing the crates use:

```
cargo release --workspace -x --no-publish
```

## Getting Started

If you have setup a development environment or installed the command line tools then you can start a server and connect a client.

We will show commands using the executable names but you can also use `cargo run` in the program directory.

To begin start a server, for example:

```
sos-server -c sandbox/config.toml
```

Then in a separate terminal create a new signing key and login vault:

```
sos-client signup -s https://localhost:5053 ./sandbox
```

This will write the signing key to the `sandbox` directory and create a new account on the server. It will also print the *keystore passphrase* for the signing key and the *encryption passphrase* for the login vault. For testing you may want to make a note of these, in the real world these passphrases need to be memorized.

Now create a shell session:

```
sos-client shell -s https://localhost:5053 -k ./sandbox/<addr>.json
```

Where `<addr>` should be changed with the public address of the signing key created during signup.

You will be prompted to enter the keystore passphrase, if the signing keystore is decrypted successfully using the passphrase you entered you will be presented with a shell prompt.

The default vault created when you signed up a new account is called *Login* so you can use it; type `use Login` to select the login vault.

Now enter your encryption passphrase to unlock the vault.

Once the vault is unlocked you can list, create, update, read and delete secrets and perform other actions such as creating snapshots or changing the vault encryption passphrase.

To see the list of available commands type `help` at the prompt.

### Audit Logs

While you make changes to a vault take a look at the audit logs:

```
sos-audit monitor sandbox/audit.dat
```

### Monitor Changes

Clients emit a stream of change events so that other clients can keep in sync; you can monitor this change stream with:

```
sos-client monitor -s https://localhost:5053 -k sandbox/<addr>.json
```

[git]: https://git-scm.com/
[wireguard]: https://www.wireguard.com/
[lcov]: https://github.com/linux-test-project/lcov
[grcov]: https://github.com/mozilla/grcov
[mkcert]: https://github.com/FiloSottile/mkcert
[browser]: https://github.com/saveoursecrets/browser
[cargo-release]: https://github.com/crate-ci/cargo-release
