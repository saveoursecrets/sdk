## Vaults

A vault is a file containing encrypted secrets. It is split into a header containing information about the encoding and cipher algorithm as well as a *name* (which is unencrypted). Vault identifiers are UUID v4.

The file format is designed to be easy to manipulate via random access seeking so that secrets can be inserted, updated and deleted efficiently.

Vaults are often also referred to as *Folders* to use a term that is more familiar to most people. These terms are used interchangeably and can be considered synonymous.

In the header of a vault file is a summary which contains the vault name, identifier, cipher, and other information. It could be considered to be a *pointer* to a vault.

Some vaults are considered to be special and are marked with bit flags to indicate these properties, some examples:

* Default folder, the primary folder for an account
* Archive folder, archived secrets can be moved here
* Contacts folder, a folder just for contacts
* Authenticator, folder for 2FA secrets (TOTP)

## Event Log

An event log is an alternative representation of a vault that is a file where events are appended and an in-memory merkle tree keeps track of the *commits* to the event log.

The primary purpose of the event log is to allow efficient syncing of vaults between different devices.

Event logs can be *reduced* to a vault file and a vault file can be *split* into an event log.

Over time an event log may grow very large or the owner may wish to discard deleted and old versions of edited secrets so an event log can be *compacted* to a sequence of events that will match the data in the corresponding vault file but discard the history. The process of compaction rewrites the entire merkle tree for the event log so is a very destructive operation from the point of view of syncing between devices as the merkle trees on the different devices will have completely diverged.

If the password of a vault is changed the entire event log (and therefore merkle tree) needs to be rewritten.

In the case of *compaction* or a change in password for a vault great care must be taken to ensure the new data can be synced at the same time.

Assuming an event log has not been rewritten then it also allows an owner to *time travel* to an earlier point in the history and recover deleted or edited secrets.

## Signing Key

The account signing key is an ECDSA (Secp256k1 curve) private key used to uniquely identity an account and verify account ownership by signing requests to a remote service.

## Account Address

An account address is an Ethereum-style address derived from the public key of the account signing key used to uniquely identify an account. This is used so that remote servers (used for syncing data) can allow account creation and modification without requiring any sign-up which may expose personally identifiable information (PII) to the server.

## Identity Vault

The Identity vault is a special kind of vault whose purpose is to protect the account signing key, provide a single password account sign in flow and to store delegated passwords. Delegated passwords are passwords for other folders managed by the account owner, each folder on disc is a separate vault file (and corresponding event log).

## Cloud Account

A cloud account refers to a paid subscription to a cloud-hosted syncing service.

## Recovery Group

A recovery group is a collection of participants that have been allocated shares in social recovery. Members of a recovery group may or may not be subscribers to a cloud account.
## Recovery Pack

A recovery pack is a mapping of vault identifiers (UUID v4) to the password for the corresponding vault. This is the map that will be encrypted during social recovery group creation.

The recovery pack must be encrypted using a secret only known to the account owner, afterwards it can be sent to a trusted third-party service for long-term storage.

The owner can then split the private key used to encrypt the recovery pack and distribute it to members of the recovery group. 

See SOCIAL-RECOVERY.md for more information on the social recovery protocol.
