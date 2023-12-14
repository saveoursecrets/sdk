## Sync

Synchronization between devices uses an eventually consistent strategy. Applications can choose how to deal with conflicts, however, due to the nature of the folder event logs and the ability to go back in time a merge on conflict with a last-write wins approach is acceptable.

Synchronization is achieved via an untrusted intermediary server.

## Transport Security

Even though all data is encrypted on the client before being sent over the network, servers **must protect** the data in transit to protect against MITM attacks that could be used to replay requests and alter the server state of an account.

Servers should either use TLS or to support HTTP transport they can use the [noise protocol](https://noiseprotocol.org/).

For development and self-hosting it is convenient to use HTTP rather than configure certificates for TLS however in a production environment we recommend securing connections with TLS.

Note that the self-hosted server implementation supports TLS certificate configuration if desired which would add an extra layer of security on top of the [noise protocol](https://noiseprotocol.org/).

## Reference Implementation

The [sos-net](/workspace/net) crate provides a client and server reference implementation. The server is suitable to be hosted on a LAN and is permissionless so should **not be exposed to the internet**, configuring a network for self-hosting is beyond the scope of this document and will vary depending upon the network.

It is **strongly recommended** to use the `allow` and `deny` access controls to determine which accounts are allowed to store data otherwise your server may be abused to store data on behalf of unknown connections.

When an `allow` configuration is present then only those addresses are allowed to connect, all other addresses will be denied.

```toml
[access]
allow = [
  "0x3ebe1c7c8e56a1e9b813073e30caf1a0cd8e7634"
]
```

If a `deny` configuration is present then any address other than the explicitly denied addresses can connect:

```toml
[access]
deny = [
  "0x7ebe1c7c89e56a1e9b813073e30caf1a0cd8e5541"
]
```

Denied addresses take precedence so take care when combining `allow` and `deny`as it's possible to block all access:

```toml
[access]
allow = [
  "0x3ebe1c7c8e56a1e9b813073e30caf1a0cd8e7634"
]
deny = [
  "0x3ebe1c7c8e56a1e9b813073e30caf1a0cd8e7634"
]
```

## Endpoints

Servers provide endpoints with different levels of protection from unauthorized access:

1) Public endpoints require no authentication.
2) Private endpoints require a signature from the account signing key.
3) Restricted endpoints require a signature from the account signing key and a signature from a trusted device.

## Event Logs

Several events logs are stored on both the client and server so that complete deterministic, incremental synchronization is possible for an account.

1) Application event log tracks changes to accounts. [^1]
2) Account event log tracks changes to folders.
3) Folder event log tracks changes to secrets in a folder.
4) File event log tracks changes to external files.

It is important to note that the folder event log stores secret data in the same encrypted format as a vault and is therefore inaccessible to the untrusted server.

The account and file logs **must not be compacted**.

## Divergence 

Event logs can only diverge under two well-defined scenarios that rewrite the event history.

1) Folder event log was compacted.
2) Folder password was changed.

## Conflict

Conflicts can happen when two devices write to the same folder whilst both devices are offline and unable to sync. [^2]

## Identification

An account is identified by the [account address](/doc/overview.md#account-address) derived from the [account signing key](/doc/overview.md#signing-key).

Client requests that access an account **must include a valid signature** and the server **must use the address of the public key from the signature** to identify the account.

Signatures prove account ownership as the account signing key is protected by the [identity vault](/doc/overview.md#identity-vault).

## Devices

Devices are represented by Ed25519 signing keys and handled differently by clients and servers.

Clients store the device signing key in a [device vault](/doc/overview.md#device-vault) and may cache meta data about trusted devices in the vault so that applications can show information about a device (hardware, operating system etc).

The [device vault](/doc/overview.md#device-vault) is **not included in synchronization** and should **never leave the device**.

When a client sends account vaults to create an account on a server it **must include** the public key of the device creating the account and the server **must trust** the device. 

### Trusting Devices

To add trusted devices the account owner can share the account [signing key](/doc/overview.md#signing-key) via a QR code (or hex-encoded string) which will allow the device to communicate with the server and add it's own public key and device meta data as a trusted device. 

Once the server has established that the device is trusted it is able to retrieve the [identity vault](/doc/overview.md#identity-vault) and account folders to perform an initial synchronization. The account owner can then provide the [primary password](/doc/overview.md#primary-password) to sign in to the account on the new device.

The server API endpoint for trusting devices **must only require a signature from the account signing key** for authentication.

### Revoking Devices

If a device has been lost or stolen an account owner can revoke the public key for the device so it is no longer trusted and will not be allowed to communicate with server endpoints that require a signature from a device.

The server API endpoint for revoking devices **must require signatures from both the account signing key and a trusted device** for authentication.

## Protocol

Let's review some terminology first.

* Let **hash** be an SHA2-256 hash
* Let a **commit tree** be a merkle tree that tracks the last leaf hash
* Let **head** be the last leaf hash
* Let **tip** be the merkle proof of **head**
* Let **commit state** be a combined **head** and **tip**
* Let **event log** own a **commit tree**
* Let **patch** be a collections of events
* Let **change set** be a collection of patches used to initialize an account
* Let **diff** contain a **patch** and the **commit state** before and after the patch was applied
* Let **sync status** include the **commit state** of every event log in an account
* Let **sync diff**  include a **diff** of every event log in an account

The terms **local** and **remote** vary by context, for a client **local** is itself and **remote** refers to a server. For a server, **local** is itself and **remote** is the client.

The behavior of clients and servers will differ slightly as they store data differently. For example, servers store vault files as head-only as they only need to prioritize storing the event logs. Whereas clients need full on-disc vaults for quick access to the secret data.

---

Client requests the **sync status** from a remote server as **remote status**.

If a **sync status** cannot be retrieved from the remote server because the account does not exist then the client should send a **change set** to the server to initialize a new account.

When a remote **sync status** is returned the client can proceed to synchronize:

1. Client compares their **local status** to the **remote status** and generates a **sync diff** including all the events that exist on local but not on remote.
2. Client sends it's **sync status** and the **sync diff** to the remote server.
3. Server receives the **sync diff** and merges the changes in each **diff** into the corresponding event logs. Merges **must be checked** such that the patch is only applied if the tip of the event log matches the before proof in the diff. For some types of events the server may need to **replay** the events such that the on disc (and in-memory) representation is correct before replying to the client. In particular, for account level events the server will need to create, update or delete folders. Replaying events **must update** the corresponding event log(s) so that the merkle tree on the server exactly matches the client.
4. Server can now compare it's updated **local status** to the **remote status** (sent by the client earlier) and generate a **sync diff** of events that exist on the server that the client has not yet received. Server replies to the client with it's updated **sync status** and the **sync diff**.
5. Client receives the updated **remote status** and the **sync diff** and merges  it into it's local storage.

[^1]: The application event log when implemented will allow account deletion to be synchronized with a server.
[^2]: Document the strategy for resolving conflicts.
