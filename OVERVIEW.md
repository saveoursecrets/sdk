## Vaults

A vault is a file containing encrypted secrets. It is split 
into a header containing information about the encoding and 
cipher algorithm as well as a *name* (which is unencrypted). 
Vault identifiers are UUID v4.

The file format is designed to be easy to manipulate via random 
access seeking so that secrets can be inserted, updated and 
deleted efficiently.

In the header of a vault file is a summary which contains the vault 
name, identifier, cipher, and other information. It could be 
considered to be a *pointer* to a vault.

Some vaults are considered to be special and are marked with 
bit flags to indicate these properties, some examples:

* Default vault, the primary vault for an account
* Archive vault , archived secrets can be moved here
* Contacts vault, a vault just for contacts
* Authenticator, vault for 2FA secrets (TOTP)

## Event Log

An event log is an alternative representation of a vault which  
is an append-only file for events, an in-memory merkle tree 
keeps track of the *commits* to the event log.

The primary purpose of the event log is to allow efficient 
syncing of vaults between different devices.

Event logs can be *reduced* to a vault file and a vault file 
can be *split* into an event log.

Over time an event log may grow very large or the owner may wish 
to discard deleted and old versions of edited secrets so an event 
log can be *compacted* to a sequence of events that will match 
the data in the corresponding vault file but discard the history. 
The process of compaction rewrites the entire merkle tree for the 
event log so is a very destructive operation from the point of view 
of syncing between devices as the merkle trees on the different 
devices will have completely diverged.

If the password of a vault is changed the entire event log 
(and therefore merkle tree) needs to be rewritten.

In the case of *compaction* or a change in password for a 
vault great care must be taken to ensure the new data can 
be synced at the same time.

Assuming an event log has not been rewritten then it also 
allows an owner to *time travel* to an earlier point in the 
history and recover deleted or edited secrets.

## Folder

Folder is the term used to refer to the combined vault and event 
log files which represent the entirety of the data required 
for a collection of secrets.

## Signing Key

The account signing key is an ECDSA (Secp256k1 curve) private 
key used to uniquely identify an account and verify account 
ownership by signing requests to a remote service.

## Account Address

An account address is an Ethereum-style address derived from 
the public key of the account signing key used to uniquely 
identify an account. An account address is used as the identifier 
so that remote servers (used for syncing data) can allow account 
creation and modification without requiring any sign-up which 
may expose personally identifiable information (PII) to the server.

## Identity Vault

The identity vault is a special kind of vault whose purpose is 
to protect the account signing key, provide a single password 
account sign in flow and to store delegated passwords. 
Delegated passwords are passwords for other folders managed 
by the account owner.

The identity vault must only be shared between devices belonging 
by the account owner.

## Device Vault

The device vault contains the signing key that identifies a single 
device and a collection of other trusted devices.

A trusted device contains meta data about a device (operating system, 
hostname, hardware information etc) that allows the owner to easily 
identify the device and the public key of the device's signing key.

The device vault must never leave that device.

Device vaults are not included in backup archives, they are lazily 
created when an account owner signs in so after restoring from a 
backup archive a new device signing key would be created and the 
account owner would need to pair with other devices to add them 
to the collection of trusted devices again.

## Cloud Account

A cloud account refers to a paid subscription to a cloud-hosted 
syncing service.

## Recovery Group

A recovery group is a collection of participants that have been 
allocated shares in the private key used for social recovery. Members 
of a recovery group may or may not be subscribers to a cloud account.

## Recovery Pack

A recovery pack is a mapping of vault identifiers (UUID v4) to 
the password for the corresponding vault. This is the map that 
will be encrypted during social recovery group creation.

The recovery pack must be encrypted using a secret only known to 
the account owner, afterwards it can be sent to a trusted 
third-party service for long-term storage.

The owner can then split the private key used to encrypt the 
recovery pack and distribute it to members of the recovery group. 

## Executor

The executor is a member of the recovery group that is authorized to 
perform the final decryption of the account owner's data.

See SOCIAL-RECOVERY.md for more information on the social recovery protocol.

## Files

Files can be *internal* (embedded in a folder) or *external* which 
encrypts the file data and stores it in a location determined by convention.

The convention for file storage is the vault identifier followed by the secret identifier and then the SHA256 hash of the encrypted file data.

Internal files are considered legacy and  *not recommended* as they 
increase the size of folders and have negative performance implications.

Support for internal files may be removed in the future so use with caution.

## User Data

User data is optional additional data that can be assigned to a secret, for example, a user might add a comment to the user data to give additional instructions to a recovery group on how to use a secret.

## Custom Fields

Custom fields are additional fields that can be assigned to the *user data* for a secret. They allow end users to manage additional data assigned to a secret adding flexibility to the shape of secret data.

Custom fields are implemented as nested secrets so whilst it is technically possible to nest custom fields it it not recommended.

It is possible to use any secret type for a custom field but that may be overwhelming from a user experience point of view so we recommend restricting the types available to custom fields, for example, limiting custom fields to notes, links, passwords and files gives a lot of flexibility without offering too many choices.

Some secret types such as *Link* and *Password* are intended to only be used in custom fields.

At the moment custom fields are not included in the search index, we may change this later.
