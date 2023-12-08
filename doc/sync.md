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

The account and file logs MUST not be compacted.

## Divergence 

Event logs can only diverge under two well-defined scenarios that rewrite the event history.

1) Folder event log was compacted.
2) Folder password was changed.

## Conflict

Conflicts can happen when two devices write to the same folder whilst both devices are offline and unable to sync. [^2]

## Identification

An account is identified by the [account address](/doc/overview.md#account-address) derived from the [account signing key](/doc/overview.md#signing-key).

Client requests that access an account MUST include a valid signature and the server MUST use the address of the public key from the signature to identify the account.

Signatures prove account ownership as the only way to access the account signing key and generate a valid signature is to unlock the [identity vault](/doc/overview.md#identity-vault).

[^1]: The application event log when implemented will allow account deletion to be synchronized with a server.
[^2]: Document the strategy for resolving conflicts.
