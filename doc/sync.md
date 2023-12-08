## Sync

Synchronization between devices uses an eventually consistent strategy. Applications can choose how to deal with conflicts, however, due to the nature of the folder event logs and the ability to go back in time a merge on conflict with a last-write wins approach is acceptable.

Synchronization is performed using an untrusted intermediary server.

## Event Logs

Several events logs are stored so that complete deterministic synchronization is possible for an account.

1) Application event log tracks changes to accounts[^1].
2) Account event log tracks changes to folders (creation, deletion etc).
3) Folder event log tracks changes to secrets in a folder.
4) File event log tracks changes to external files.

It is important to note that the folder event log stores secret data in the same encrypted format as a vault and is therefore inaccessible to the untrusted server.

It is expected that the account and file account logs are never compacted.

## Divergence 

Event logs can only be completely diverged under two well-defined scenarios that rewrite the event history.

1) Folder event log was compacted.
2) Folder password was changed.

[^1]: The application event log when implemented will allow account deletion to be synchronized with a server.

