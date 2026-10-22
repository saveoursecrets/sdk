# Shared Folders

Shared folders use asymmetric encryption to protect secrets that can be accessed across multiple accounts.

The implementation uses X25519 public key encryption to multiple recipients using [AGE V1](https://github.com/C2SP/C2SP/blob/main/age.md) provided by the [AGE library](https://docs.rs/age/latest/age/).

In order for people to discover participants for shared folders we implement simple public key infrastructure (PKI) using the existing tenant-specific SQLite database (see the [migration](/crates/database/sql_migrations/V3__shared_folders.sql) for the relevant tables).

A shared folder implies network connectivity so the functions for shared folders are exposed on [NetworkAccount](/crates/net/src/account/network_account.rs) with the exception of the helper function `prepare_shared_folder()` which was added to [LocalAccount](/creates/accunts/src/local_account.rs) to create the vault with the correct cipher and flags.

## Terminology

* Recipient: an account that has enabled sharing by configuring a name (and possibly email) visible to other accounts.
* Participant: a recipient that is cryptographically participating in a shared folder.
* Owner: the creator of a shared folder.

## Recipients, participants and discovery

We extend on the existing X25519 [Recipient](https://docs.rs/age/latest/age/x25519/struct.Recipient.html) notion to provide a name and optional email associated with an account in the SQLite database.

The server then provides endpoints for accounts to create and update their own recipient information which will enable folder sharing for an account. Participants may be discovered by searching for other recipients by name (or email).

Once a recipient has been discovered the owner creating (or updating the recipients) for a shared folder can send a folder invite; when a recipient accepts a folder invite they will then have access to the shared folder which will be treated like any other folder except that it will use asymmetric encryption.

## Updating recipients, re-encryption and sync

When the owner of a shared folder wants to add or remove a recipient it will require re-encrypting all the secrets in the folder to cryptographically allow or disallow access to the secrets in the folder.

These changes can be sent as a series of update events which will make non-destructive changes to the event log and allow the usual sync algorithm to apply changes for all recipients.

However, when a recipient is removed by the owner we need to consider that fact that a removed recipient may be able to access the existing secrets using the time travel feature, for example, by accessing secrets defined in earlier versions of the event log. Therefore, we should recommend or force that when removing a recipient the event log is compacted to remove access to earlier versions of the encrypted secrets therefore denying access to the removed recipient. This will generate a hard conflict for other recipients that still have access to the folder and they would need to force pull the new version of the shared folder.

It is worth noting though that removing a recipient from a shared folder, whilst it may (assuming compaction and sync) cryptographically deny the person access to the secrets the shared folder owner needs to consider all the secrets in the folder as compromised (as the removed recipient may have already copied the secrets elsewhere) so all the secrets in the shared folder should be rotated by the owner to truly deny access to the removed recipient and protect the shared secrets.

## Server storage

In order to facilitate shared folders on the server with minimal changes to the sync algorithm the server storage library now manages a collection of `shared_folders` and the folder event logs for each account refer to the shared folder event log using atomic reference counting (`Arc`). For the server to detect shared folders it is essential that the `VaultFlags::SHARED` bit is set correctly which the library code enforces in `prepare_shared_folder()`.

