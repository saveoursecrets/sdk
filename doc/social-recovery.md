# Social Recovery

This document describes the design of the Save-Our-Secrets social recovery scheme.

## Summary

A _social recovery mechanism_ allows the owner of a Save-Our-Secrets account to create and distribute shares, a threshold number of which can be used to download the encrypted SoS account after a countdown, if the owner is not present. Once downloaded, those same shares can then be used to reconstitute an encryption key using [Shamir's Secret Sharing][sss] which decrypts a subset of vaults within the account. This generalized approach to recovery also implicitly supports 1-of-1 recovery tokens.

## Requirements

The primary focus of the social recovery scheme is as a digital inheritance mechanism, for passwords, secrets, and cryptocurrency. It can also be used as a _forgotten password_ mechanism. This implies several important requirements.

- Social recovery must not require access to the account owner's original vault files or computer, which may be inaccessible if the owner is gone.
- Social recovery must not require knowledge of a specific master password, which the account owner may have forgotten.
- The above requirements imply the need for a backend server, to achieve universal availability of data. However, due to the sensitive nature of the data involved, any such server must not be trusted with direct access to plaintext secrets at any time.
- Recovery shares must be distributed in forms which anyone can easily hold and keep safe, requiring no technical expertise.
  - (optional) If some shareholders are Save-Our-Secrets users, then shares can be distributed digitally over an end-to-end-encrypted transport channel.
- An account owner can configure multiple recovery groups with different shareholders, any of which can recover the account.
  - (optional) A group-threshold can be configured, so than some minimum number of groups must cooperate to recover the account.
- Recovery shares must not need to be constantly updated (unless the account owner desires it).
- Recovery shares should be revokable at any time by the account owner.
- The account owner should be able to issue new recovery shares at any time.

There are also requirements concerning the recovery process itself.

- The recovery process must occur over a prolonged period of time, so that an account owner can thwart any attempts at theft conducted by a dishonest recovery group.
- The recovery shareholders can initiate the recovery countdown only if a threshold of shareholders agree on whom to send the encrypted recovery package to. Since this cannot be enforced cryptographically, the SoS backend server must enforce it.
- When the recovery countdown starts, the account owner and all other shareholders in the group must be alerted with push notifications or email.
- Once the recovery countdown is completed, the backend server must distribute an encrypted package which only a threshold of the recovery group can cooperatively decrypt.
- The recovery group must be able to decrypt the exact vaults selected by the account owner by cooperating in-person.
  - (optional) The recovery group should be able to cooperatively decrypt the recovery pack remotely, still without revealing the plaintext vault to the SoS backend server.
- After recovery, the old shares need to be revoked as each share has been exposed to the other shareholders.
- (optional) Shareholders can return control of the account to the rightful owner by letting them set a new account encryption password.

## Mathematical Notation

- Let $H(x)$ denote a cryptographically secure hash function.
  - $H(x, y)$ denotes the hash function operating on multiple input arguments (possibly delimited).
- Let $\mathbb{Z}\_q$ denote the finite field of integers modulo the prime number $q$.
- Let $G$ denote the base point of an elliptic curve group of order $q$, for which the elliptic curve discrete log problem is hard.
- Let $Q$ be some other point on the same curve, with a provably unknown discrete log relative to $G$.
- Let $\sum\_{i=1}^n x_i$ denote summation notation, i.e. $x_0 + x_1 + ... + x_n$.

## Stages

The protocol proceeds in stages:

1. **Setup** - The account owner sets up their account to support recovery of specific vaults, and distributes shares to their recovery group(s).
2. **Initiation** - One shareholder initiates the recovery process. If enough of the other shareholders do the same within a configured time window, then the countdown begins.
3. **Countdown** - During a configured time window, the rightful account owner can step in and abort the recovery.
4. **Transmission** - The encrypted recovery pack is transmitted to the recipient designated by shareholders.
5. **Decryption** - The shareholders cooperate (in-person or remotely) to decrypt the recovery pack.
6. **Finalization** - The group confirms they received and decrypted the account. Their shares are revoked and the account is configured with a new password, or alternatively, deleted from the server.

## Stage 1: Setup

The account owner at this stage has access to their full SoS account and client. She decides to set up a social recovery group on their SoS account.

Let `account_id` denote a server-side identifier for the account to be recovered.

The account owner chooses several other public parameters to be shared with the server later:

| Parameter | Type | Description | Example |
|:---------:|:----:|:-----------:|:-------:|
| `init_window` | Duration | A time window within which shareholders must cooperate to initiate the recovery countdown. | 24h |
| `countdown_duration` | Duration | How long the countdown lasts. The longer this is, the more time an account owner will have to abort the recovery process, but the longer the recovery group must wait to finish recovery. | 2 weeks |
| `vaults` | Set | The set of vaults which the account owner would like to be recoverable by this group. | |
| `group_index` | uint4 | The index of the group. If this is the first recovery group to be registered on the user's account, this will be zero. Otherwise it should be incremented upwards as more groups are added. This index does not need to be unique, but it would improve user experience if it were. | 0 |
| $t$ | uint8 | The group recovery threshold. If $t$ or more shareholders cooperate, they can recover and decrypt the SoS account. | 3 |

### Choosing Shareholders

The account owner selects a set of `shareholders`. These are trusted individuals who will keep their respective recovery shares safe, and who promise use the shares to recover the SoS account only if the true account owner asks them to, or dies.

Let $n$ be the number of `shareholders`, which can be at most 256.

Shareholder contact information is collected from the account owner on the SoS client. Email addresses, telephone numbers, SoS account identifiers, or optionally other contact methods in the future, e.g. Telegram/WhatsApp, can be collected. All this info is encapsulated in the `shareholders` array.

### Vault Encryption

The account owner chooses a `cipher` for encrypting the vault pack, and randomly generates the **group key** $k$ by sampling from $\mathbb{Z}\_q$.

Using the set of `vaults` he selected, the account owner constructs the `recovery_pack_header`. This header is essentially a mapping of vault identifiers to encrypted vault passphrases. The passphrase for each vault in `vaults` is encrypted using the chosen `cipher`, under the group key $k$. If the integer form of $k$ is not a suitable encryption key for the chosen `cipher`, it can be hashed into one using a key-derivation function such as HKDF. The `recovery_pack_header` should include the `cipher` and optionally the KDF algorithm if needed.

### Sharing

The account owner breaks the group key $k$ into shares on the client side using [Shamir's Secret Sharing][sss] so that it can later be distributed to the shareholders.

We denote the secret sharing polynomial $f(x)$ of degree $t-1$ as follows:

$$ f(x) = k + \sum_{i=1}^{t-1} a_i x^i $$
$$ f(x) = k + a_1 x + a_2 x^2 + ... + a_{t-1} x^{t-1} $$

The coefficients $\\{a_1, a_2, ... a_{t-1}\\}$ are sampled randomly from $\mathbb{Z}\_q$ by the SoS client. Each coefficient can be thought of as a private key, mapping one-way to a multiple of the elliptic curve base point $G$ (a public key). The polynomial $f(x)$ and its coefficients will be kept secret by the account owner.

The SoS client computes the shares $\\{s_1, s_2, ... s_n\\}$ by evaluating $f(x)$ at various values of $x$, called _share indexes._ Each share $s_i$ has a corresponding index $i$, such that $f(i) = s_i$.

The account owner constructs two other polynomials related to $f(x)$:

1. The _share verification polynomial:_

$$ F(x) = f(x) \cdot G = k G + \sum_{i=1}^{t-1} a_i x^i G $$

2. The _contact sharing polynomial:_

$$ Z(x) = f(x) \cdot Q = k Q + \sum_{i=1}^{t-1} a_i x^i Q $$

The function $f(x)$ outputs scalars (private keys) in $\mathbb{Z}\_q$. Constrasingly, $F(x)$ and $Z(x)$ output elliptic curve points, which are multiples of $G$ or $Q$ respectively.

Note that $F(x)$ and $Z(x)$ are [Verifiable Secret Sharing][vss] polynomials. If we treat each share $s_i$ as a secret key, then $F(i)$ outputs the public key $s_i G$, while $Z(i)$ outputs the public key $s_i Q$.

The client will give $F(x)$ to the server as-is, which will allow the server to identify valid shares.

### Contact Encryption

The client picks $t-1$ share indexes which are reserved and guaranteed not to be used by real shares. The most practical option would be to use indexes counting down from the curve order $q$ (kind of like using negative numbers) which - assuming we index real shares starting from zero - are all but certain never to be issued for actual recovery shareholders.

For each of these $t-1$ reserved share indexes $q - t \lt j \lt q$, the client computes the curve points $S_j' = Z(j)$. Let $\hat{S}$ denote these $t-1$ points. $\hat{S}$ will be uploaded to the SoS backend server, so that if the server learns any other evaluation $Z(j)$ where $j \le q - t$, then it can interpolate the full polynomial $Z(x)$.

The client computes the _contact encryption key_ $c = H(Z(0))$, and uses $c$ to encrypt `shareholders` into `shareholders_enc`. The `shareholders_enc` binary blob can be padded to avoid exposing the shareholders count $n$. `shareholders_enc` should also embed `cipher` and optional KDF algorithm identifiers to aid the server in later decryption.

By encrypting `shareholders` in this way, we ensure that the server will be able to decrypt `shareholders_enc` only if it learns any evaluation of $Z(x)$ which it doesn't already know. Any of the shareholders who knows $s_i$ will be able to provide that, by simply computing $s_i Q$. We thus avoid the need to expose $n$, or to embed additional keys into recovery shares.

### Upload

The account owner uploads the following data to the SoS server to complete setup:

| Data point | Description |
|:----------:|:-----------:|
| `init_window` | The recovery initiation time window. |
| `countdown_duration` | The time buffer after recovery initiation, after which the recovery pack will be distributed. |
| `group_index` | The index of the recovery group, identifying it among other groups for the same account. |
| `recovery_pack_header` | Contains a mapping of `vaults` to encrypted passphrases, a `cipher`, and optionally a KDF algorithm for deriving the encryption key from $k$. |
| $F(x)$ | The group key public verification polynomial. Specifically, the coefficient points are uploaded. |
| $\hat{S}$ | $t-1$ shares of the contact-sharing polynomial $Z(x)$. |
| `shareholders_enc` | The shareholder contact info, encrypted under $c = H(Z(0))$. |

The server stores this data sorted in a binary tree, keyed by the `account_id`, so that it can be easily fetched later at recovery time.

The server should reply with an error if the `group_index` is already taken, or if the vaults in the `recovery_pack_header` do not exist.

### Distribution

Shares are encoded and displayed to the account owner, who will distribute them to shareholders.

Let `version` be a 4-bit version number, which identifies the particular recovery share format, length, and algorithm set. The `version` allows us flexibility to change the share format later without breaking compatibility with older shares.

Let `account_id_prefix` be the first 4 bytes of `account_id`. We use only the first 4 bytes to save space in the encoded share.

Each share embeds the following data fields:

| Data point | Description | Bit size |
|:----------:|:-----------:|:--------:|
| `version` | Version byte. | 4 bits |
| `account_id_prefix` | The prefix of the account ID to which this recovery share belongs. | 32 bits |
| `group_index` | The index of the recovery group, identifying it among other groups for the same account. | 4 bits |
| $i$ | The share index, such that $f(i) = s_i$ | 8 bits |
| $s_i$ | The secret share of $k$ | 256 bits |
| `checksum` | A checksum of the other fields to verify correctness. | 4 bits |

Combined, a single share requires a total of **308 bits** of information. This is small enough that shares can be formatted using a mnemonic encoding wordlist such as [BIP39], allowing them to be written on paper and kept offline. Shares of this size would be represented as **a phrase of 28 words** if using a [BIP39] word list.

The raw binary representation of a share (minus the `checksum`) could also be formatted as a QR code and printed out.

### Backup & Sync

The account owner's SoS client should save the following data points inside a vault:

| Data point | Description |
|:----------:|:-----------:|
| `init_window` | The recovery initiation time window. |
| `countdown_duration` | The time buffer after recovery initiation, after which the recovery pack will be distributed. |
| `group_index` | The index of the recovery group, identifying it among other groups for the same account. |
| $f(x)$ | The group key secret sharing polynomial. This consists of the secret $k$ and the coefficients $\\{a_1, a_2, ... a_{t-1}\\}$. |
| $\hat{S}$ | $t-1$ shares of the contact-sharing polynomial $Z(x)$. |
| `shareholders` | The plaintext shareholder contact info. |

At regular intervals, the account owner's SoS client will synchronize their encrypted vaults with the SoS backend server. These vaults are encrypted under the same passphrases originally used to produce the `recovery_pack_header`. If one of these vault passphrases is changed, then the `recovery_pack_header` stored on the server must be updated by an active push from the client.

The client may also push a new `shareholders_enc` blob to the SoS backend server at any time the account owner wishes to update the contact details of their `shareholders`.

If the account owner wishes to revoke a recovery group, she simply tells the server to delete the recovery group info, including the crucial `recovery_pack_header`, without which the vaults cannot be decrypted, even if the group key $k$ is known. This also allows the owner an avenue to rotate shares, by recreating the group immediately afterward.

If the account owner wishes to issue a new share of $k$ without invalidating the old ones, she computes $s_i = f(i)$ at the new share index $i$, and distributes $s_i$ to the new shareholder.

## Stage 2: Initiation

TODO

## Stage 3: Countdown

TODO

## Stage 4: Transmission

TODO

## Stage 5: Decryption

TODO

## Stage 6: Finalization

# Appendix

TODO:
- Security
- Privacy

[sss]: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
[vss]: https://en.wikipedia.org/wiki/Verifiable_secret_sharing
[BIP39]: https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md
