use crate::{
    commit::CommitHash, Error, Result, SecretId, SecretPath, VaultId,
};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// External file name is an SHA2-256 checksum of
/// the encrypted file contents.
#[derive(
    Default, Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize,
)]
pub struct ExternalFileName(#[serde(with = "hex::serde")] [u8; 32]);

impl fmt::Debug for ExternalFileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ExternalFileName")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl From<ExternalFileName> for [u8; 32] {
    fn from(value: ExternalFileName) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for ExternalFileName {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for ExternalFileName {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<&ExternalFileName> for CommitHash {
    fn from(value: &ExternalFileName) -> Self {
        CommitHash(value.0)
    }
}

impl TryFrom<&[u8]> for ExternalFileName {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let value: [u8; 32] = value.try_into()?;
        Ok(value.into())
    }
}

impl fmt::Display for ExternalFileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for ExternalFileName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let buf: [u8; 32] = hex::decode(s)?.as_slice().try_into()?;
        Ok(Self(buf))
    }
}

/// Pointer to an external file.
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub struct ExternalFile(SecretPath, ExternalFileName);

impl From<ExternalFile> for (SecretPath, ExternalFileName) {
    fn from(value: ExternalFile) -> Self {
        (value.0, value.1)
    }
}

impl ExternalFile {
    /// Create a new external file reference.
    pub fn new(path: SecretPath, file_name: ExternalFileName) -> Self {
        Self(path, file_name)
    }

    /// Vault identifier.
    pub fn vault_id(&self) -> &VaultId {
        &self.0 .0
    }

    /// Secret identifier.
    pub fn secret_id(&self) -> &SecretId {
        &self.0 .1
    }

    /// File name.
    pub fn file_name(&self) -> &ExternalFileName {
        &self.1
    }
}

impl fmt::Display for ExternalFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.vault_id(),
            self.secret_id(),
            self.file_name()
        )
    }
}

impl FromStr for ExternalFile {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.splitn(3, '/');
        let vault_id = parts
            .next()
            .ok_or(Error::InvalidExternalFile(s.to_owned()))?;
        let secret_id = parts
            .next()
            .ok_or(Error::InvalidExternalFile(s.to_owned()))?;
        let file_name = parts
            .next()
            .ok_or(Error::InvalidExternalFile(s.to_owned()))?;
        let vault_id: VaultId = vault_id.parse()?;
        let secret_id: SecretId = secret_id.parse()?;
        let file_name: ExternalFileName = file_name.parse()?;
        Ok(Self(SecretPath(vault_id, secret_id), file_name))
    }
}
