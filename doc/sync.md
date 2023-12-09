## Sync

Synchronization between devices uses an eventually consistent strategy. Applications can choose how to deal with conflicts, however, due to the nature of the folder event logs and the ability to go back in time a merge on conflict with a last-write wins approach is acceptable.

Synchronization is performed using an untrusted intermediary server.

## Event Logs

Several events logs are stored so that complete deterministic, incremental synchronization is possible for an account.

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

To add trusted devices the account owner can share the account [signing key](/docs/overview.md#signing-key) via a QR code (or text) which will allow the device to communicate with the server and add it's own public key and device meta data as a trusted device. 

Once the server has established that the device is trusted it is able to retrieve the [identity vault](/docs/overview.md#identity-vault) and account folders to perform an initial synchronization. The account owner can then provide the [primary password](/docs/overview.md#primary-password) to sign in to the account on the new device.

The server API endpoint for trusting devices should only require a signature from the account signing key for authentication.

### Revoking Devices

If a device has been lost or stolen an account owner can revoke the public key for the trusted device so it is no longer allowed to communicate with the server.

The server API endpoint for revoking devices **must require signatures from both the account signing key and a trusted device** for authentication.

[^1]: The application event log when implemented will allow account deletion to be synchronized with a server.
[^2]: Document the strategy for resolving conflicts.
