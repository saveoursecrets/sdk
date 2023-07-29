# Save Our Secrets Library

> Save our Secrets (SOS) is a cross-platform, distributed, encrypted database with a focus on security, integrity and redundancy. It can be used to store private secrets such as account passwords, notes, certificates and encryption keys.

This repository contains the core library code and several command line interface (CLI) tools.

* [Design](#design) Brief overview of the design
* [Layout](#repository-layout) Guide to the repository layout
* [Development](#development) Set up a development environment
* [Getting Started](#getting-started) Getting started guide for developers 

## Design

A vault is a collection of encrypted secrets. Vaults can be represented as both an append-only log file for synchronization and a compact binary file for archiving and portability. Bi-directional conversion between the append-only log and compact binary file is straightforward; the library provides functions to *reduce* the append-only log to a vault and *split* a vault into it's header and a collection of events that can be appended to a log.

Synchronization between nodes is done using an append-only log file of events; a Merkle tree is computed for each log file using the hash of the data for each record. By comparing Merkle proofs we can easily determine which tree is ahead or whether the trees have diverged; much in the same way that [git][] synchronizes source code.

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
* [ ] `PEER`: Synchronization of nodes using a p2p network.

### Conflicts

Conflicts are categorised into *soft conflicts* which can be automatically resolved via synchronization and *hard conflicts* which may require user approval to be resolved.

#### Soft Conflict

Soft conflicts occur when a node tries to make changes to another node but cannot as their commit trees are out of sync but have not diverged. These sorts of conflicts can be resolved by pushing local changes or pulling remote changes to synchronize; if the synchronization is successful the calling node can try again.

#### Hard Conflict

The system is eventually consistent except in the case of two events; when a WAL is compacted to prune history or when the encryption password for a vault is changed. Either of these events will completely rewrite the append-only log and therefore the vault commit trees will have diverged. If all nodes are connected when these events occur then it is possible to synchronize automatically but if a node is offline (or an error occurs) then we have a conflict that must be resolved; we call this a *hard conflict*.

[git]: https://git-scm.com/
[wireguard]: https://www.wireguard.com/
[lcov]: https://github.com/linux-test-project/lcov
[grcov]: https://github.com/mozilla/grcov
[mkcert]: https://github.com/FiloSottile/mkcert

© Copyright Save Our Secrets Pte Ltd 2022; all rights reserved.
