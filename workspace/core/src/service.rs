//! Traits and in-memory implementation for services that provide
//! access to a vault.

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::{
    crypto::authorize::{jwt, Authorization, Challenge, ChallengeResponse},
    vault::Vault,
};

/// Trait for services that handle authorization.
pub trait AuthorizationService {
    /// Client wants to login to a vault so generate a challenge.
    fn login(&mut self, name: &str) -> Result<Challenge>;

    /// Attempt to authorize with a challenge response.
    fn authorize(&mut self, response: ChallengeResponse) -> Result<jwt::Token>;
}

/// Trait for service that exposes access to multiple vaults.
pub trait VaultService: AuthorizationService {
    /// Add a vault.
    fn add_vault(&mut self, name: String, vault: Arc<RwLock<Vault>>) -> Result<()>;
}

/// Implementation for a service that accesses vaults loaded into memory.
pub struct MemoryService {
    authorization: Authorization,
    vaults: HashMap<String, Arc<RwLock<Vault>>>,
    key_pair: jwt::KeyPair,
}

impl MemoryService {
    /// Create an in-memory service.
    pub fn new(key_pair: jwt::KeyPair, vaults: HashMap<String, Arc<RwLock<Vault>>>) -> Self {
        Self {
            authorization: Default::default(),
            vaults,
            key_pair,
        }
    }
}

impl VaultService for MemoryService {
    fn add_vault(&mut self, name: String, vault: Arc<RwLock<Vault>>) -> Result<()> {
        if self.vaults.get(&name).is_some() {
            bail!("vault already exists with name {}", name);
        }
        self.vaults.insert(name, vault);
        Ok(())
    }
}

impl AuthorizationService for MemoryService {
    fn login(&mut self, name: &str) -> Result<Challenge> {
        if let Some(_) = self.vaults.get(name) {
            let challenge = Challenge::new(name.to_string());
            self.authorization.add(challenge.clone());
            return Ok(challenge);
        }
        bail!("vault {} not found", name);
    }

    fn authorize(&mut self, response: ChallengeResponse) -> Result<jwt::Token> {
        if let Some(name) = self.authorization.vault_name(&response) {
            if let Some(vault) = self.vaults.get(&name) {
                let vault = vault.read().unwrap();
                if let Ok(_) = self.authorization.authorize(vault.public_keys(), &response) {
                    let token = jwt::authorize(&self.key_pair, jwt::claims(name))?;
                    return Ok(token);
                } else {
                    bail!("not authorized")
                }
            } else {
                bail!("vault {} not found", name);
            }
        } else {
            bail!("authorization challenge not found")
        }
    }
}
