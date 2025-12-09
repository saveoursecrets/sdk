# Shared Folders

Shared folders use asymmetric encryption to protect secrets that can be accessed across multiple accounts.

The implementation uses X25519 public key encryption to multiple recipients using the [AGE V1](https://github.com/C2SP/C2SP/blob/main/age.md) provided by the [AGE library](https://docs.rs/age/latest/age/).

In order for people to discover participants for shared folders we implement simple public key infrastructure (PKI) using the existing tenant-specific SQLite database (see the [migration](/crates/database/sql_migrations/V3__shared_folders.sql) for the relevant tables).

A shared folder implies network connectivity so the functions for shared folders are exposed on [NetworkAccount](/crates/net/src/account/network_account.rs) with the exception of the helper function `prepare_shared_folder()` which was added to [LocalAccount](/creates/accunts/src/local_account.rs) to create the vault with the correct cipher and flags.

## Recipients, Participants and Discovery

We extend on the existing X25519 [Recipient](https://docs.rs/age/latest/age/x25519/struct.Recipient.html) notion to provide a name and optional email associated with an account in the SQLite database.

The server then provides endpoints for accounts to create and update their own recipient information which will enable folder sharing for an account. Participants may be discovered by searching for other recipients by name (or email).

Once a recipient has been discovered the owner creating (or updating the recipients) for a shared folder can send a folder invite. Updating recipients poses several challenges which we will address separately.

When a recipient accepts a folder invite they will then have access to the shared folder which will be treated like any other folder except that it will use asymmetric encryption.

## Updating Recipients, Re-encryption and forced syncing

TODO: document the challenges with changing recipients of a shared folder
