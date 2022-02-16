//! Vault client traits and in-memory implementation.
use anyhow::Result;
//use binary_rw::{BinaryReader, BinaryWriter, Stream};

use k256::ecdsa::{
    signature::{Signature as EcdsaSignature, Signer},
    Signature, SigningKey,
};

use crate::{
    crypto::authorize::{jwt, ChallengeResponse, PrivateKey},
    service::VaultService,
    //traits::{Decode, Encode},
    //vault::Vault,
};

/// Trait for clients that can interact with a vault file.
pub trait VaultClient {
    /// Set the key used for encryption and decryption.
    fn set_encryption_key(&mut self, key: Option<Vec<u8>>);

    /// Get the encryption and decryption key.
    fn encryption_key(&self) -> &Option<Vec<u8>>;

    /// Attempt to login to a vault.
    fn login(&mut self, name: &str) -> Result<()>;
}

/// Client implementation used to access in-memory vault data.
///
/// Used by the command line interface.
pub struct MemoryClient<'a> {
    service: &'a mut dyn VaultService,
    signing_key: SigningKey,
    encryption_key: Option<Vec<u8>>,
    token: Option<jwt::Token>,
}

impl<'a> MemoryClient<'a> {
    /// Create a new local client for the given vault.
    pub fn new(
        service: &'a mut impl VaultService,
        private_key: &PrivateKey,
        //encryption_key: Vec<u8>,
    ) -> Result<Self> {
        Ok(Self {
            service,
            signing_key: private_key.try_into()?,
            encryption_key: None,
            token: None,
        })
    }
}

impl VaultClient for MemoryClient<'_> {
    fn set_encryption_key(&mut self, key: Option<Vec<u8>>) {
        self.encryption_key = key;
    }

    fn encryption_key(&self) -> &Option<Vec<u8>> {
        &self.encryption_key
    }

    fn login(&mut self, name: &str) -> Result<()> {
        let challenge = self.service.login(name)?;
        let signature: Signature = self.signing_key.sign(challenge.message());
        let bytes = signature.as_bytes().to_vec();
        let response = ChallengeResponse::new(challenge.id().clone(), bytes);
        let token = self.service.authorize(response)?;
        self.token = Some(token);
        Ok(())
    }
}

/*
/// Vault access available at runtime with the index
/// decrypted.
pub struct RuntimeAccess<'a> {
    vault: &'a mut Vault,
}

/// Decrypted entry in the vault index.
pub type IndexEntry = (String, MetaData);

/// Decrypted index meta data.
pub struct RuntimeIndex {
    data: Vec<IndexEntry>,
}


impl Encode for RuntimeIndex {
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()> {
        writer.write_usize(self.data.len())?;
        for item in &self.data {
            item.encode(writer)?;
        }
        Ok(())
    }
}

impl Decode for RuntimeIndex {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        let length = reader.read_usize()?;
        for _ in 0..length {
            let mut meta: IndexEntry = Default::default();
            meta.decode(reader)?;
            self.data.push(meta);
        }
        Ok(())
    }
}


impl Encode for IndexEntry {
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()> {
        writer.write_string(&self.0)?;
        self.1.encode(writer)?;
        Ok(())
    }
}

impl Decode for IndexEntry {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        self.0 = reader.read_string()?;
        let mut meta: MetaData = Default::default();
        meta.decode(reader)?;
        self.1 = meta;
        Ok(())
    }
}

/// Meta data for an encrypted entry.
#[derive(Default)]
pub struct MetaData {}

impl Encode for MetaData {
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()> {
        Ok(())
    }
}

impl Decode for MetaData {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        Ok(())
    }
}

*/
