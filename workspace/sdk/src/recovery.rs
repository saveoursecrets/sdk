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

use crate::{
    crypto::{
        csprng, AeadPack, Cipher, KeyDerivation,
        PrivateKey, Seed,
    },
    decode, encode,
    signer::{ecdsa::SingleParty, Signer},
    vault::VaultId,
    Error, Result,
};
use k256::{
    elliptic_curve::PrimeField, NonZeroScalar, Scalar,
    SecretKey,
};
use secrecy::SecretString;
use std::collections::HashMap;
use vsss_rs::{combine_shares, shamir};

/// Recovery data maps vault identifiers to the
/// vault passwords.
#[derive(Default)]
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
#[derive(Default)]
pub struct RecoveryOptions {
    /// Cipher for encryption and decryption.
    pub(crate) cipher: Cipher,
    /// Key derivation function.
    pub(crate) kdf: KeyDerivation,
    /// Threshold for secret recovery.
    pub(crate) threshold: u16,
    /// Number of secret shares to split.
    pub(crate) limit: u16,
}

impl RecoveryOptions {
    /// Create new recovery options.
    pub fn new(
        threshold: u16,
        limit: u16,
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
}

/// Shares in the secret used to encrypt the
/// recovery data.
pub struct RecoveryShares {
    pub shares: Vec<Vec<u8>>,
}

/// Encrypted recovery data.
#[derive(Default)]
pub struct RecoveryPack {
    pub(crate) options: RecoveryOptions,
    pub(crate) salt: String,
    pub(crate) seed: Seed,
    pub(crate) data: AeadPack,
}

impl RecoveryPack {
    /// Create a new recovery pack encrypting the
    /// data using the given signing key.
    pub async fn encrypt(
        data: &RecoveryData,
        signer: &SingleParty,
        options: RecoveryOptions,
    ) -> Result<(RecoveryPack, RecoveryShares)> {
        let signer_bytes = signer.to_bytes();
        let signer_hex = hex::encode(signer_bytes);
        let password = SecretString::new(signer_hex);
        let deriver = options.kdf.deriver();
        let salt = KeyDerivation::generate_salt();
        let seed = KeyDerivation::generate_seed();
        let key = PrivateKey::Symmetric(deriver.derive(
            &password,
            &salt,
            Some(&seed),
        )?);

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
                options,
                salt: salt.to_string(),
                seed,
                data: encrypted_data,
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
        let password = SecretString::new(signer_hex);

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{vault::VaultId, encode, decode};
    use anyhow::Result;
    use secrecy::ExposeSecret;

    #[tokio::test]
    pub async fn recovery_symmetric() -> Result<()> {
        let mock_id = VaultId::new_v4();
        let mock_password = "mock-password";
        let mut data: RecoveryData = Default::default();
        data.vaults_mut().insert(
            mock_id.clone(),
            SecretString::new(mock_password.to_string()),
        );

        let signer = SingleParty::new_random();
        let threshold = 2;
        let limit = 3;
        let options = RecoveryOptions::new(threshold, limit, None, None);

        let (pack, recovery) =
            RecoveryPack::encrypt(&data, &signer, options).await?;
        assert_eq!(3, recovery.shares.len());
        
        // Verify encoding and decoding
        let encoded_pack = encode(&pack).await?;
        let pack: RecoveryPack = decode(&encoded_pack).await?;

        // Not enough shares
        let less_than_threshold = RecoveryShares {
            shares: recovery.shares[0..1].to_vec(),
        };
        assert!(pack.decrypt(&less_than_threshold).await.is_err());

        // Number of shares meets the threshold (2)
        let recovery_shares = RecoveryShares {
            shares: recovery.shares[0..2].to_vec(),
        };
        let (recovered_signer, recovered_data) =
            pack.decrypt(&recovery_shares).await?;
        let recovered_password =
            recovered_data.vaults().get(&mock_id).unwrap();
        assert_eq!(signer.to_bytes(), recovered_signer.to_bytes());
        assert_eq!(mock_password, recovered_password.expose_secret());

        Ok(())
    }
}
