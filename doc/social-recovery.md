# Social Recovery

This document describes the design of the Save-Our-Secrets social recovery scheme.

## Summary

A _social recovery mechanism_ allows the owner of a Save-Our-Secrets account to create and distribute shares, a threshold number of which can be used to download the encrypted SoS account after a countdown, if the owner is not present. Once downloaded, those same shares can then be used to reconstitute an encryption key using [Shamir's Secret Sharing][sss] which decrypts a subset of vaults within the account.

This generalized approach to recovery supports 1-of-1 recovery tokens, or 1-of-n recovery groups, with or without the explicit consent of the account owner.

## Requirements

The primary focus of the social recovery scheme is as a digital inheritance mechanism, for passwords, secrets, and cryptocurrency. It can also be used as a _forgotten password_ mechanism. This implies several important requirements.

- The account owner can choose which vaults are recoverable.
- The account owner has a special share which might help to decrypt extra vaults.
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
  - The account owner's share can be used to bypass this delay.
- The recovery shareholders can initiate the recovery countdown only if a threshold of shareholders agree on whom to send the encrypted recovery package to. Since this cannot be enforced cryptographically, the SoS backend server must enforce it.
- The recovery shareholders should not need to be physically present in the same room for them to initiate the recovery countdown.
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
- Let $H'(x)$ denote a hash function which maps to $\mathbb{Z}\_q$. For example: $H'(x) = H(x) \mod q$
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

The account owner at this stage has access to their full SoS account and client. She decides to set up a social recovery group on her SoS account.

Let `account_id` denote a server-side identifier for the account to be recovered.

The account owner generates the **owner share secret** $w$, which is randomly sampled from $\mathbb{Z}\_q$. The owner share pubkey is computed as $W = wG$. This will be used to identify the owner's recovery share to the server. The owner share can be reused across multiple recovery groups.

The account owner chooses several other public parameters to be shared with the server later:

| Parameter | Type | Description | Example |
|:---------:|:----:|:-----------:|:-------:|
| `init_window` | Duration | A time window within which shareholders must cooperate to initiate the recovery countdown. | 24h |
| `countdown_duration` | Duration | How long the countdown lasts. The longer this is, the more time an account owner will have to abort the recovery process, but the longer the recovery group must wait to finish recovery. | 2 weeks |
| `owner_vaults` | Set | The set of vaults which the account owner would like to be recoverable independently using only the account owner's own share. Unless the account owner desires the _whole account_ to be recoverable, this set should not include the identity vault. | |
| `group_vaults` | Set | The set of vaults which the account owner would like to be recoverable by this group in their absence. Unless the account owner desires the _whole account_ to be recoverable, this set should not include the identity vault. | |
| `joint_vaults` | Set | The set of vaults which the account owner would like to be recoverable by this group if the account owner himself also cooperates. Unless the account owner desires the _whole account_ to be recoverable, this set should not include the identity vault. | |
| $g$ | uint4 | The index of the group. If this is the first recovery group to be registered on the user's account, this will be zero. Otherwise it should be incremented upwards as more groups are added. This index does not need to be unique, but it would improve user experience if it were. | 0 |
| $t$ | uint8 | The group recovery threshold. If $t$ or more shareholders cooperate, they can recover and decrypt the SoS account. | 3 |

### Choosing Shareholders

The account owner selects a set of `shareholders`. These are trusted individuals who will keep their respective recovery shares safe, and who promise to use the shares to recover the SoS account only if the true account owner asks them to, or dies.

Let $n$ be the number of `shareholders`, which can be at most 256.

Shareholder contact information is collected from the account owner on the SoS client. Email addresses, telephone numbers, SoS account identifiers, or optionally other contact methods in the future, e.g. Telegram/WhatsApp, can be collected. All this info is encapsulated in the `shareholders` array.

### Vault Encryption

The account owner chooses a `cipher` for encrypting the vault pack, and randomly generates the **group key** $k$ by sampling from $\mathbb{Z}\_q$. The group key $k$ will be controlled jointly by the recovery group _and_ the account owner, with threshold $t$. It encrypts a header which, once decrypted, can be used to decrypt selected vaults.

Using the sets of vaults he selected, the account owner constructs the `recovery_pack_header`. This header is essentially a mapping of vault identifiers to encrypted vault passphrases.

- The passphrase for each vault in `owner_vaults` is encrypted using the chosen `cipher`, under the owner share key $w$. <!-- TODO only upload this once -->
- The passphrase for each vault in `group_vaults` is encrypted using the chosen `cipher`, under the group key $k$.
- The passphrase for each vault in `joint_vaults` is encrypted using the chosen `cipher`, under the aggregated group-and-owner key $k + w$.

If the integers in $\mathbb{Z}\_q$ are not suitable encryption keys for the chosen `cipher`, they can be hashed into one using a key-derivation function such as HKDF.

The `recovery_pack_header` should include the `cipher` and optionally the KDF algorithm if needed.

### Sharing

The account owner must break the group key $k$ into shares on the client side using [Shamir's Secret Sharing][sss] so that it can be distributed to the shareholders.

However, we cannot use traditional SSS without excluding the account owner from the recovery group. We want the account owner's share to behave like one of the group's shares, in that it should count toward the threshold $t$ needed to recover the group key $k$. However, we also can't use the owner share secret $w$ as a share of $k$, because then it could be discovered by $t$ or more members of the recovery group.

We instead use _the hash of $w$ and the group index $g$, mapped onto $\mathbb{Z}\_q$_ as a share.

Let $s_1$ represent the owner's share of the group key $k$. We define $s_1$ as:

$$ s_1 := H'(w, g) $$

Then we generate $t-2$ additional shares $\\{s_2, s_3, ..., s_{t-1}\\}$, randomly sampled from $\mathbb{Z}\_q$.

We then interpolate the Shamir Secret Sharing polynomial $f(x)$ as the degree $t-1$ polynomial which passes through the set of $t$ points:

$$ \\{ (0, k),\ (1, s_1),\ (2, s_2),\ (3, s_3),\ ... (t-1, s_{t-1}) \\} $$

This polynomial has degree at most $t-1$, since it passes through a chosen set of $t$ points. Once interpolated, we can compute its coefficients and represent it in standard form.

$$ f(x) = k + \sum_{i=1}^{t-1} a_i x^i $$
$$ f(x) = k + a_1 x + a_2 x^2 + ... + a_{t-1} x^{t-1} $$

The coefficients $\\{a_1, a_2, ... a_{t-1}\\}$ are distributed randomly among $\mathbb{Z}\_q$. Each coefficient can be thought of as a private key, mapping one-way to a multiple of the elliptic curve base point $G$ (a public key). The polynomial $f(x)$ and its coefficients will be kept secret by the account owner.

<sub>Note this approach differs from the traditional approach of Shamir Secret Sharing polynomial generation. Normally, one would first fix the _coefficients_ of $f(x)$ and then evaluate it to get all the shares at once. Instead, we sampled _a few_ of the evaluations, reconstructed the coefficients of $f(x)$ by interpolation, and then evaluated it a few more times to get the remaining shares. This allows us to fix $s_1$ as one of the shares in-advance.</sub>

This approach ensures that the owner share key $w$ cannot be learned by the recovery group, but the account owner can still use their share secret $w$ to compute and contribute to the recovery of $k$.

The SoS client computes the remaining shares $\\{s_t, s_{t+1}, ... s_n\\}$ by evaluating $f(x)$ at various values of $x$, called _share indexes._ Each share $s_i$ has a corresponding index $i$, such that $f(i) = s_i$.

The account owner constructs two other polynomials related to $f(x)$:

1. The _share verification polynomial:_

$$ F(x) = f(x) \cdot G = k G + \sum_{i=1}^{t-1} a_i x^i G $$

2. The _contact sharing polynomial:_

$$ Z(x) = f(x) \cdot Q = k Q + \sum_{i=1}^{t-1} a_i x^i Q $$

The function $f(x)$ outputs scalars (private keys) in $\mathbb{Z}\_q$. Contrastingly, $F(x)$ and $Z(x)$ output elliptic curve points, which are multiples of $G$ or $Q$ respectively.

Note that $F(x)$ and $Z(x)$ are [Verifiable Secret Sharing][vss] polynomials. If we treat each share $s_i$ as a secret key, then $F(i)$ outputs the public key $s_i G$, while $Z(i)$ outputs the public key $s_i Q$.

The client will give $F(x)$ to the server as-is, which will allow the server to identify valid shares.

### Contact Encryption

The client picks $t-1$ share indexes which are reserved and guaranteed not to be used by real shares. The most practical option would be to use indexes counting down from the curve order $q$ (kind of like using negative numbers) which - assuming we index real shares starting from zero - are all but certain never to be issued for actual recovery shareholders.

For each of these $t-1$ reserved share indexes $q - t \lt j \lt q$, the client computes the curve points $S_j' = Z(j)$. Let $\hat{S}$ denote these $t-1$ points. $\hat{S}$ will be uploaded to the SoS backend server, so that if the server learns any other evaluation $Z(j)$ where $j \le q - t$, then it can interpolate the full polynomial $Z(x)$.

The client computes the _contact encryption key_ $c = H(Z(0))$, and uses $c$ to encrypt `shareholders` into `shareholders_enc`. The `shareholders_enc` binary blob can be padded to avoid exposing the shareholders count $n$. `shareholders_enc` should also embed `cipher` and optional KDF algorithm identifiers to aid the server in later decryption.

By encrypting `shareholders` in this way, we ensure that the server will be able to decrypt `shareholders_enc` only if it learns any evaluation of $Z(x)$ which it doesn't already know. Any of the shareholders who knows $s_i$ will be able to provide that, by simply giving the server $S_i' = s_i Q$. We thus avoid the need to expose $n$, or to embed additional keys into recovery shares.

### Upload

The account owner uploads the following data to the SoS server to complete setup:

| Data point | Description |
|:----------:|:-----------:|
| `init_window` | The recovery initiation time window. |
| `countdown_duration` | The time buffer after recovery initiation, after which the recovery pack will be distributed. |
| $g$ | The index of the recovery group, identifying it among other groups for the same account. |
| `recovery_pack_header` | Contains a mapping of vaults to encrypted passphrases, a `cipher`, and optionally a KDF algorithm for deriving the encryption key from $k$. |
| $F(x)$ | The group key public verification polynomial. Specifically, the coefficient points are uploaded. |
| $\hat{S}$ | $t-1$ shares of the contact-sharing polynomial $Z(x)$. |
| `shareholders_enc` | The shareholder contact info, encrypted under $c = H(Z(0))$. |

The server stores this data sorted in a binary tree, keyed by the `account_id`, so that it can be easily fetched later at recovery time.

The server should reply with an error if the $g$ is already taken, or if the vaults in the `recovery_pack_header` do not exist.

### Distribution

Shares are encoded and displayed to the account owner, who will distribute them to shareholders.

Let `version` be a 4-bit version number, which identifies the particular recovery share format, length, and algorithm set. The `version` allows us flexibility to change the share format later without breaking compatibility with older shares.

Let `account_id_prefix` be the first 4 bytes of `account_id`. We use only the first 4 bytes to save space in the encoded share.

Each share embeds the following data fields:

| Data point | Description | Bit size |
|:----------:|:-----------:|:--------:|
| `version` | Version byte. | 4 bits |
| `account_id_prefix` | The prefix of the account ID to which this recovery share belongs. | 32 bits |
| $g$ | The index of the recovery group, identifying it among other groups for the same account. | 4 bits |
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
| $g$ | The index of the recovery group, identifying it among other groups for the same account. |
| $f(x)$ | The group key secret sharing polynomial. This consists of the secret $k$ and the coefficients $\\{a_1, a_2, ... a_{t-1}\\}$. |
| $\hat{S}$ | $t-1$ shares of the contact-sharing polynomial $Z(x)$. |
| `shareholders` | The plaintext shareholder contact info. |

At regular intervals, the account owner's SoS client will synchronize their encrypted vaults with the SoS backend server. These vaults are encrypted under the same passphrases originally used to produce the `recovery_pack_header`. If one of these vault passphrases is changed, then the `recovery_pack_header` stored on the server must be updated by an active push from the client.

The client may also push a new `shareholders_enc` blob to the SoS backend server at any time the account owner wishes to update the contact details of their `shareholders`.

If the account owner wishes to revoke a recovery group, she simply tells the server to delete the recovery group info, including the crucial `recovery_pack_header`, without which the vaults cannot be decrypted, even if the group key $k$ is known. This also allows the owner an avenue to rotate shares, by recreating the group immediately afterward.

If the account owner wishes to issue a new share of $k$ without invalidating the old ones, she computes $s_i = f(i)$ at the new share index $i$, and distributes $s_i$ to the new shareholder.

## Stage 2: Initiation

There are three different scenarios for recovery:

1. The account owner independently recovering their vaults.
2. A recovery group independently recovering the account's vaults.
3. A recovery group and the account owner jointly recovering the account's vaults.

The set of vaults which can be recovered will depend on which of these recovery scenarios is occurring.

If only the account owner wants to participate in recovery, then no threshold is required - only the account owner's share. Otherwise, to initiate the countdown, a `recovery_group` at least a threshold $t$ of `shareholders` must cooperate, possibly including the account owner herself.

We assume each shareholder is in contact through some outside medium. The account owner has either requested assistance from them, or the account owner has died and their account needs to be recovered.

### Identifying the Group

First things first: The SoS backend server must be able to identify which account the group wants to recover, and also which specific recovery group for that account is trying to do so, and which of the three scenarios is unfolding.

Recall that each share embeds `account_id_prefix` and $g$. A shareholder will upload both to the server at recovery initiation time. The server will look up all accounts starting with `account_id_prefix`, which will probably be only the one - maybe 2 or 3 if we're very unlucky. The server then checks if either account has a recovery group with the given $g$.

This is the server's source of truth for which account is being recovered and which group is doing the recovering.

The recovery group must now prove that they hold shares in one of these recovery groups, and that they agree on what they want to do with the account upon recovery.

### Proving Cooperation

A `destination` must be chosen. This will be the recipient of the recovery pack, who will ultimately decrypt and regain access to the account. `destination` could be an email address, phone number, or SoS account ID - Any contact method, basically. If the account owner is alive, this should obviously be them. If not, it can be a trusted executor, family, etc.

Once the `recovery_group` agrees on `destination` out-of-band, they must use their shares to initiate the recovery countdown by demonstrating their cooperation and intent to recover.

Recall this requirement:

> The recovery shareholders should not need to be physically present in the same room for them to initiate the recovery countdown.

We need a way for each shareholder to prove their commitment to `destination`, while also proving they hold a valid share of $f(x)$.

Recall that each share $s_i = f(i)$ is basically a secret key, which has corresponding public key $S_i = f(i) \cdot G = F(i)$. Also recall that the SoS backend server knows the group key public verification polynomial $F(x)$, and can thus calculate any $F(i)$.

Therefore, to commit to `destination` and prove their legitimacy, shareholders can simply sign `destination` as a message, using their share $s_i$ as a secret key. Let `dest_sig` be that signature.

### Decrypting Shareholder Contact Info

Remember how the server has `shareholders_enc` - an encrypted blob of shareholder contact info.

Once a single shareholder starts recovery, all other shareholders should be sent a notification which informs them that recovery has been initiated. The server can only do this if it can decrypt `shareholders_enc`.

As described above in Stage 1, we can provide the server with means for this decryption, by providing the curve point $S_i' = s_i Q$. The server can then use $S_i'$ plus the $t-1$ shares it already knows to interpolate the polynomial $Z(x)$, and thus compute the contact encryption key $c = H(Z(0))$, and decrypt `shareholders_enc`.

### Initial Upload

To initiate recovery, the first recovery shareholder must enter their share into an SoS client, which then computes and uploads the following data to the SoS backend server:

| Data point | Description |
|:----------:|:-----------:|
| `account_id_prefix` | The prefix of the account ID to which this recovery share belongs. |
| $g$ | The index of the recovery group, identifying it among other groups for the same account. |
| $i$ | The share index. |
| $S_i' = s_i Q$ | Shareholder contact info share. |
| `destination` | A contact method describing where to send the recovery pack. Determines the ultimate beneficiary of the recovery process. |
| `dest_sig` | A signature made by $s_i$ on `destination`. |
| `owner_sig` | A signature made by $w$ on `destination`. Required if $i = 1$ (the owner share). |

<!-- TODO independent recovery request parameters -->

### Verification

The SoS backend server can use `account_id_prefix` and $g$ to look up a set of recovery groups. Each recovery group has the group key verification polynomial $F(x)$.

For each possible recovery group, the server computes $S_i = F(i)$, and checks if `dest_sig` is a valid signature on `destination` under the key $S_i$.

If $i = 1$, the share should belong to the account owner, so `owner_sig` is checked. It must be a valid signature on `destination` under the owner share pubkey $W$.

The server also attempts to decrypt `shareholders_enc` by using $S_i'$ to interpolate $Z(x)$.

If any of the above steps fail, the server must fail the recovery attempt and optionally report it to the account owner.

Note that if `dest_sig` is valid, but decryption of `shareholders_enc` fails, then the server **must not proceed,** because the shareholder might be attempting to perform the account takeover independently and stealthily without cooperation of other shareholders.

### Confirmations

After the initial upload, the server sends notifications to all other `shareholders`. This notification might include a hyperlink to a web-app or a deep link to the SoS client app. It should include `destination` in obvious clear text, so that shareholders can verify who will reap the rewards of the account recovery process.

If the shareholder agrees with the recovery attempt, they can submit their share into the client app. Internally, the app will then perform most of the same logic as the initial shareholder did, except subsequent shareholders do not need to compute and upload $S_i' = s_i Q$. Specifically they must submit these fields:

| Data point | Description |
|:----------:|:-----------:|
| `account_id_prefix` | The prefix of the account ID to which this recovery share belongs. Optionally we could also embed the full `account_id` in the hyperlink at this point, since it might already be known server-side. |
| $g$ | The index of the recovery group, identifying it among other groups for the same account. |
| $i$ | The share index. |
| `destination` | A contact method describing where to send the recovery pack. Determines the ultimate beneficiary of the recovery process. |
| `dest_sig` | A signature made by $s_i$ on `destination`. |
| `owner_sig` | A signature made by $w$ on `destination`. Required if $i = 1$ (the owner share). |

The SoS backend server verifies this confirmation attempt in exactly the same way as the initial recovery submission.

If at least $t$ distinct shareholders (optionally including the account owner) submit valid `dest_sig`s within `init_window` time after the first recovery submission _for the same_ `account_id`, and _for the same_ `destination`, then a threshold group of shareholders is confirmed to exist, and they are cooperating. The server then proceeds to the next stage.

If `init_window` elapses without sufficient confirmations, the server abandons the recovery attempt.

### Aborting

Once the initial upload is submitted, the server also sends a notification to the account owner, which allows them to abort the recovery attempt unilaterally. This is a safety measure which ensures a colluding group of shareholders cannot steal the account from the rightful owner.

## Stage 3: Countdown

Once a sufficient number of signed confirmations are received from shareholders, the _countdown_ begins, for a length of `countdown_duration`. This is a time delay enforced by the SoS backend server. The countdown gives the rightful account owner time to receive the notification, to recognize and abort a non-consensual recovery attempt.

During the countdown, the SoS backend server's job is to preserve the account's encrypted data, and wait for a possible abort request by the account owner.

If the account owner's share signed off on the recovery, and if the owner configured the group accordingly, then the countdown stage is skipped, and the next stage (transmission) occurs immediately after the $t$-th shareholder's signature is received by the server.

## Stage 4: Transmission

If `countdown_duration` elapses without an abort issued - or is skipped by the account owner - then the recovery is deemed authentic. The server can now send the recovery pack to the agreed `destination`. The recovery pack contains:

| Data point | Description |
|:----------:|:-----------:|
| `recovery_pack_header` | Contains a mapping of vaults to encrypted passphrases, a `cipher`, and optionally a KDF algorithm for deriving the encryption key from $k$. |
| `vaults` | The set of encrypted vaults whose passwords are encrypted in the header. This does not include event logs, only the most up-to-date snapshot of each encrypted vault. |

Upon receipt, the `destination` agent cannot immediately decrypt the `vaults` unless they have the appropriate shares. `destination` is probably a trusted executor or the account owner herself, depending on the situation.

## Stage 5: Decryption

To decrypt the recovery pack, shares must be brought together on the same trusted machine. Note that these do not necessarily have to be the same set of shares as the `recovery_group`. However, if the account owner participated in recovery initiation, then `vaults` may include some vaults which only the account owner's share can decrypt.

The group uses their shares to interpolate the original secret sharing polynomial $f(x)$, and then compute the group key $k = f(0)$. If the account owner's share is present, it is decoded into the owner secret $w$, which may be used towards recovering $k$.

Depending on the recovery scenario, the final decryption key is either:

1. The account owner's key $w$
2. The group key $k$
3. An aggregated group-and-owner key $w + k$

This key decrypts the passwords in the `recovery_pack_header`. Those passwords can then be used to decrypt the relevant vaults.

## Stage 6: Finalization

TODO

# Appendix

## Live Modification

TODO

## Security

TODO

## Privacy

TODO

[sss]: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
[vss]: https://en.wikipedia.org/wiki/Verifiable_secret_sharing
[BIP39]: https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md
