//! Types for encrypting recovery data and splitting the secrets
//! for social recovery.
//!
//! Recovery data maps vault identifiers to passwords. Recovery data is
//! encrypted using the private account signing key and the signing key
//! is then split using Shamir's secret sharing (SSS) so that the
//! recovery shares can be distributed amongst trusted parties.
//!
//! This module does not contain any networking or logic for
//! secret share distribution.

use crate::{Error, Result};
use hex;
use k256::{elliptic_curve::PrimeField, NonZeroScalar, Scalar, SecretKey};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use sos_core::{
    crypto::{AeadPack, Cipher, KeyDerivation, PrivateKey, Seed},
    decode, encode, AccountId,
};
use sos_core::{csprng, VaultId};
use sos_signer::{ecdsa::SingleParty, Signer};
use std::collections::HashMap;
use uuid::Uuid;
use vsss_rs::{combine_shares, shamir};

/// Type for recovery group identifiers.
pub type RecoveryGroupId = Uuid;

/// Type for recovery pack identifiers.
pub type RecoveryPackId = Uuid;

/// Recovery data maps vault identifiers to the
/// vault passwords.
#[derive(Default, Clone)]
pub struct RecoveryData {
    vaults: HashMap<VaultId, SecretString>,
}

impl RecoveryData {
    /// Get the underlying vault secrets.
    pub fn vaults(&self) -> &HashMap<VaultId, SecretString> {
        &self.vaults
    }

    /// Get a mutable reference to the underlying vault secrets.
    pub fn vaults_mut(&mut self) -> &mut HashMap<VaultId, SecretString> {
        &mut self.vaults
    }
}

/// Recovery options.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RecoveryOptions {
    /// Cipher for encryption and decryption.
    pub(crate) cipher: Cipher,
    /// Key derivation function.
    pub(crate) kdf: KeyDerivation,
    /// Threshold for secret recovery.
    pub(crate) threshold: u8,
    /// Number of secret shares to split.
    pub(crate) limit: u8,
}

impl RecoveryOptions {
    /// Create new recovery options.
    pub fn new(
        threshold: u8,
        limit: u8,
        cipher: Option<Cipher>,
        kdf: Option<KeyDerivation>,
    ) -> Self {
        Self {
            threshold,
            limit,
            cipher: cipher.unwrap_or_default(),
            kdf: kdf.unwrap_or_default(),
        }
    }

    /// Encryption cipher algorithm.
    pub fn cipher(&self) -> &Cipher {
        &self.cipher
    }

    /// Key derivation function.
    pub fn kdf(&self) -> &KeyDerivation {
        &self.kdf
    }

    /// Limit of secret shares.
    pub fn limit(&self) -> u8 {
        self.limit
    }

    /// Threshold for secret shares.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }
}

/// Shares in the secret used to encrypt the
/// recovery data.
#[derive(Default)]
pub struct RecoveryShares {
    /// Secret shares.
    pub shares: Vec<Vec<u8>>,
}

/// Encrypted recovery data.
#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RecoveryPack {
    pub(crate) id: RecoveryPackId,
    pub(crate) options: RecoveryOptions,
    pub(crate) vaults: Vec<VaultId>,
    pub(crate) salt: String,
    #[serde_as(as = "Base64")]
    pub(crate) seed: Seed,
    pub(crate) data: AeadPack,
    pub(crate) account_id: AccountId,
}

impl RecoveryPack {
    /// Unique identifier for this pack.
    pub fn id(&self) -> &RecoveryPackId {
        &self.id
    }

    /// Recovery options.
    pub fn options(&self) -> &RecoveryOptions {
        &self.options
    }

    /// Account identifier for this recovery pac.
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Identifiers for vaults that are included in the recovery pack.
    pub fn vaults(&self) -> &[VaultId] {
        self.vaults.as_slice()
    }

    /*
    /// Create a new recovery pack encrypting the
    /// data using the given signing key.
    pub async fn encrypt(
        data: &RecoveryData,
        signer: &SingleParty,
        options: RecoveryOptions,
    ) -> Result<(RecoveryPack, RecoveryShares)> {
        let address = signer.address()?;
        let signer_bytes = signer.to_bytes();
        let signer_hex = hex::encode(signer_bytes);
        let password = signer_hex.into();
        let deriver = options.kdf.deriver();
        let salt = KeyDerivation::generate_salt();
        let seed = KeyDerivation::generate_seed();
        let key = PrivateKey::Symmetric(deriver.derive(
            &password,
            &salt,
            Some(&seed),
        )?);

        let vaults: Vec<VaultId> = data.vaults.keys().map(|k| *k).collect();

        let encoded = encode(data).await?;
        let encrypted_data = options
            .cipher
            .encrypt_symmetric(&key, &encoded, None)
            .await?;

        let sk = SecretKey::from_bytes(&signer.0.to_bytes())?;
        let secret = *sk.to_nonzero_scalar();
        let mut rng = csprng();
        let key_shares = shamir::split_secret::<Scalar, u8, Vec<u8>>(
            options.threshold as usize,
            options.limit as usize,
            secret,
            &mut rng,
        )
        .map_err(|e| Error::Vsss(e.to_string()))?;

        Ok((
            Self {
                id: RecoveryPackId::new_v4(),
                options,
                vaults,
                salt: salt.to_string(),
                seed,
                data: encrypted_data,
                account_id,
            },
            RecoveryShares { shares: key_shares },
        ))
    }

    /// Decrypt this recovery pack using recovery key shares.
    pub async fn decrypt(
        &self,
        recovery: &RecoveryShares,
    ) -> Result<(SingleParty, RecoveryData)> {
        let scalar: Scalar = combine_shares(&recovery.shares)
            .map_err(|e| Error::Vsss(e.to_string()))?;

        let nzs = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
        let sk = SecretKey::from(nzs);

        let signer_bytes = sk.to_bytes();
        let signer_hex = hex::encode(signer_bytes);
        let password = signer_hex.into();

        let deriver = self.options.kdf.deriver();
        let salt = KeyDerivation::parse_salt(&self.salt)?;
        let key = PrivateKey::Symmetric(deriver.derive(
            &password,
            &salt,
            Some(&self.seed),
        )?);

        let encoded_data = self
            .options
            .cipher
            .decrypt_symmetric(&key, &self.data)
            .await?;

        let signer_slice: [u8; 32] = signer_bytes.as_slice().try_into()?;
        let signer: SingleParty = (&signer_slice).try_into()?;

        Ok((signer, decode::<RecoveryData>(&encoded_data).await?))
    }
    */
}

/// Participant in a recovery group.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryParticipant<T> {
    user_info: T,
}

impl<T> RecoveryParticipant<T> {
    /// Create a new recovery participant.
    pub fn new(user_info: T) -> Self {
        Self { user_info }
    }

    /// User information for the participant.
    pub fn info(&self) -> &T {
        &self.user_info
    }
}

/// Recovery group information.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryGroup<T> {
    id: RecoveryGroupId,
    name: String,
    participants: Vec<RecoveryParticipant<T>>,
    options: RecoveryOptions,
    pack: RecoveryPack,
    public: bool,
}

impl<T> RecoveryGroup<T> {
    /// Unique identifier for this group.
    pub fn id(&self) -> &RecoveryGroupId {
        &self.id
    }

    /// Name of the recovery group.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Collection of recovery group participants.
    pub fn participants(&self) -> &[RecoveryParticipant<T>] {
        self.participants.as_slice()
    }

    /// Recovery pack.
    pub fn recovery_pack(&self) -> &RecoveryPack {
        &self.pack
    }

    /// Account identifier.
    pub fn account_id(&self) -> &AccountId {
        &self.pack.account_id
    }

    /// Limit on secret shares.
    pub fn limit(&self) -> u8 {
        self.options.limit
    }

    /// Threshold of secret shares required for recovery.
    pub fn threshold(&self) -> u8 {
        self.options.threshold
    }

    /// Whether this recovery group contains participants
    /// other than the account owner.
    pub fn public(&self) -> bool {
        self.public
    }

    /// Builder for a recovery group.
    pub fn builder() -> RecoveryGroupBuilder<T> {
        RecoveryGroupBuilder {
            name: String::from("Untitled"),
            participants: Vec::new(),
            options: Default::default(),
            signer: None,
            data: Default::default(),
            threshold: None,
            public: false,
        }
    }
}

impl<T> From<RecoveryGroup<T>> for RecoveryPack {
    fn from(value: RecoveryGroup<T>) -> Self {
        value.pack
    }
}

/// Recovery group builder.
///
/// Unless explicitly set the threshold will default to the number
/// of participants.
pub struct RecoveryGroupBuilder<T> {
    name: String,
    participants: Vec<RecoveryParticipant<T>>,
    options: RecoveryOptions,
    signer: Option<SingleParty>,
    data: RecoveryData,
    threshold: Option<u8>,
    public: bool,
}

impl<T> RecoveryGroupBuilder<T> {
    /// Add a participant to the recovery group.
    ///
    /// # Panics
    ///
    /// If the number of participants exceeds `u8::MAX`.
    pub fn add_participant(mut self, user: RecoveryParticipant<T>) -> Self {
        self.participants.push(user);
        if self.participants.len() > u8::MAX as usize {
            panic!("too many recovery group participants");
        }
        self.options.limit = self.participants.len() as u8;
        self
    }

    /// Set the recovery group name.
    pub fn name(mut self, name: String) -> Self {
        self.name = name;
        self
    }

    /// Indicate whether this recovery group contains
    /// participants other than the account owner.
    pub fn public(mut self, public: bool) -> Self {
        self.public = public;
        self
    }

    /// Set the recovery group data.
    pub fn data(mut self, data: RecoveryData) -> Self {
        self.data = data;
        self
    }

    /// Set the threshold for recovery.
    pub fn threshold(mut self, threshold: u8) -> Self {
        self.threshold = Some(threshold);
        self
    }

    /// Set the cipher used to encrypt the recovery pack.
    pub fn cipher(mut self, cipher: Cipher) -> Self {
        self.options.cipher = cipher;
        self
    }

    /// Set the key derivation function used when
    /// encrypting the recovery pack.
    pub fn kdf(mut self, kdf: KeyDerivation) -> Self {
        self.options.kdf = kdf;
        self
    }

    /// Set the account signing key.
    pub fn signer(mut self, signer: SingleParty) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Build the recovery group.
    pub async fn build(
        mut self,
    ) -> Result<(RecoveryGroup<T>, RecoveryShares)> {
        let threshold = self
            .threshold
            .unwrap_or_else(|| self.participants.len() as u8);

        if threshold < 2 {
            return Err(Error::RecoveryThreshold(threshold));
        }
        self.options.threshold = threshold;

        todo!("restore recovery group handling");

        /*
        let signer = self.signer.take().ok_or_else(|| Error::NoSigner)?;
        let (pack, shares) =
            RecoveryPack::encrypt(&self.data, &signer, self.options.clone())
                .await?;
        Ok((
            RecoveryGroup {
                id: RecoveryGroupId::new_v4(),
                name: self.name,
                participants: self.participants,
                options: self.options,
                pack,
                public: self.public,
            },
            shares,
        ))
        */
    }
}
