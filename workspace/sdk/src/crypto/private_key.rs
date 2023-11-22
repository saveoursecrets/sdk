//! Private key types.
use age::x25519::Identity;
use argon2::password_hash::SaltString;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use std::convert::AsRef;
use std::fmt;

use crate::{
    crypto::{KeyDerivation, Seed, Cipher, AeadPack},
    Error, Result,
};

/// Access key used to unlock a vault.
#[derive(Clone)]
pub enum AccessKey {
    /// Password access.
    Password(SecretString),
    /// Asymmetric private key.
    Identity(Identity),
}

impl From<SecretString> for AccessKey {
    fn from(value: SecretString) -> Self {
        Self::Password(value)
    }
}

impl From<Identity> for AccessKey {
    fn from(value: Identity) -> Self {
        Self::Identity(value)
    }
}

impl From<AccessKey> for SecretString {
    fn from(value: AccessKey) -> Self {
        match value {
            AccessKey::Password(password) => password,
            AccessKey::Identity(id) => id.to_string(),
        }
    }
}

impl AccessKey {
    /// Convert this access key into a private key.
    pub fn into_private(
        self,
        kdf: &KeyDerivation,
        salt: &SaltString,
        seed: Option<&Seed>,
    ) -> Result<PrivateKey> {
        match self {
            Self::Password(ref password) => {
                let deriver = kdf.deriver();
                Ok(PrivateKey::Symmetric(
                    deriver.derive(password, salt, seed)?,
                ))
            }
            Self::Identity(id) => Ok(PrivateKey::Asymmetric(id)),
        }
    }
}

impl fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => f.debug_struct("Password").finish(),
            Self::Identity(_) => f.debug_struct("Identity").finish(),
        }
    }
}

impl PartialEq for AccessKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Password(a), Self::Password(b)) => {
                a.expose_secret() == b.expose_secret()
            }
            (Self::Identity(a), Self::Identity(b)) => {
                a.to_string().expose_secret() == b.to_string().expose_secret()
            }
            _ => false,
        }
    }
}

impl Eq for AccessKey {}

/// Private key variants.
pub enum PrivateKey {
    /// Private key used for symmetric ciphers.
    Symmetric(DerivedPrivateKey),
    /// Private key used for asymmetric ciphers.
    Asymmetric(Identity),
}

/// Encapsulates the bytes for a derived symmetric secret key.
pub struct DerivedPrivateKey {
    inner: SecretVec<u8>,
}

impl DerivedPrivateKey {
    /// Create a new random 32-byte secret key.
    pub fn generate() -> Self {
        use crate::crypto::csprng;
        use rand::Rng;
        let bytes: [u8; 32] = csprng().gen();
        Self {
            inner: SecretVec::new(bytes.to_vec()),
        }
    }

    /// Convert from a PEM-encoded key.
    pub fn from_pem(key: &str) -> Result<Self> {
        let pem = pem::parse(key)?;
        let contents = pem.contents();
        Ok(Self {
            inner: SecretVec::new(contents.to_vec()),
        })
    }

    /// Convert this key to a PEM-encoded string.
    pub fn to_pem(&self) -> String {
        pem::encode(&pem::Pem::new(
            "PRIVATE KEY",
            self.inner.expose_secret().as_slice(),
        ))
    }

    /// Create a new derived private key.
    pub(crate) fn new(inner: SecretVec<u8>) -> Self {
        Self { inner }
    }
}

impl AsRef<[u8]> for DerivedPrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.inner.expose_secret()
    }
}

impl From<Vec<u8>> for DerivedPrivateKey {
    fn from(value: Vec<u8>) -> Self {
        Self { inner: SecretVec::new(value) }
    }
}

/// Secure access key is an encrypted representation 
/// of an access key so that it can be transferred 
/// between accounts on different devices via an intermediary 
/// such as a relay server.
///
/// Typically the account signing key would be used as the secret 
/// used to encrypt and decrypt the access key.
///
/// Used to enable syncing folders between accounts on 
/// different devices.
pub enum SecureAccessKey {
    /// Password access key variant.
    Password(Cipher, AeadPack),
    /// Identity (asymmetric) access key variant.
    Identity(Cipher, AeadPack),
}

impl SecureAccessKey {
    /// Encrypt an access key.
    pub async fn encrypt(
        key: &AccessKey,
        secret_key: impl AsRef<[u8]>,
        cipher: Option<Cipher>) -> Result<SecureAccessKey> {

        let secret = match key {
            AccessKey::Password(vault_passphrase) => vault_passphrase.clone(),
            AccessKey::Identity(id) => id.to_string(),
        };

        let cipher = cipher.unwrap_or_default();
        let private_key = PrivateKey::Symmetric(
            secret_key.as_ref().to_vec().into());
        let aead = cipher.encrypt_symmetric(
            &private_key, secret.expose_secret().as_bytes(), None).await?;

        Ok(match key {
            AccessKey::Password(_) => SecureAccessKey::Password(cipher, aead),
            AccessKey::Identity(_) => SecureAccessKey::Identity(cipher, aead),
        })
    }

    /// Decrypt an access key.
    pub async fn decrypt(
        key: &SecureAccessKey,
        secret_key: impl AsRef<[u8]>) -> Result<AccessKey> {
        let (cipher, aead) = match key {
            Self::Password(cipher, aead) => (cipher, aead),
            Self::Identity(cipher, aead) => (cipher, aead),
        };
        let private_key = PrivateKey::Symmetric(
            secret_key.as_ref().to_vec().into());

        let buffer = cipher.decrypt_symmetric(&private_key, aead).await?;
        let value = std::str::from_utf8(&buffer)?;
        let secret = SecretString::new(value.to_owned());

        Ok(match key {
            Self::Password(_, _) => AccessKey::Password(secret),
            Self::Identity(_, _) => {
                let identity: Identity = value.parse().map_err(
                    |s: &'static str| {
                        Error::AgeIdentityParse(s.to_string())
                    })?;
                AccessKey::Identity(identity)
            },
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;
    use age::x25519::Identity;
    use crate::signer::ecdsa::SingleParty;

    #[tokio::test]
    async fn secure_access_key_password() -> Result<()> {
        let password = SecretString::new("mock-password".to_string());
        let password_access = AccessKey::Password(password);

        let signer = SingleParty::new_random();
        let secret_key = signer.0.to_bytes();

        let sendable = SecureAccessKey::encrypt(
            &password_access, &secret_key, None).await?;

        let access_key = SecureAccessKey::decrypt(
            &sendable, &secret_key).await?;

        assert_eq!(password_access, access_key);
        Ok(())
    }

    #[tokio::test]
    async fn secure_access_key_identity() -> Result<()> {
        let identity = Identity::generate();
        let identity_access = AccessKey::Identity(identity);

        let signer = SingleParty::new_random();
        let secret_key = signer.0.to_bytes();

        let sendable = SecureAccessKey::encrypt(
            &identity_access, &secret_key, None).await?;

        let access_key = SecureAccessKey::decrypt(
            &sendable, &secret_key).await?;

        assert_eq!(identity_access, access_key);
        Ok(())
    }
}
