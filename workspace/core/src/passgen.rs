//! Utility for generating random passwords.
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use zxcvbn::{zxcvbn, Entropy};
use chbs::{
    config::{BasicConfig, BasicConfigBuilder},
    word::WordSampler,
};

use crate::{diceware::{generate_passphrase_config, default_config}, Result};

const ROMAN_LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const ROMAN_UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const PUNCTUATION: &str = "!\"#$%&'()*+,-./:;<=>?@`~\\]^_{}";

/// Generated password result.
#[derive(Debug, Clone)]
pub struct PasswordResult {
    /// The generated password.
    pub password: SecretString,
    /// The computed entropy for the password.
    pub entropy: Entropy,
}

/// Options for password generation.
#[derive(Debug, Clone)]
pub struct PasswordGen {
    length: usize,
    characters: Vec<&'static str>,
    diceware: Option<BasicConfig<WordSampler>>,
}

impl PasswordGen {
    /// Create a new password generator.
    pub fn new(length: usize) -> Self {
        Self {
            length,
            characters: vec![],
            diceware: None,
        }
    }

    /// Create with lowercase and uppercase character sets.
    pub fn new_alpha(length: usize) -> Self {
        Self::new(length).upper().lower()
    }

    /// Create with numeric digits only.
    pub fn new_numeric(length: usize) -> Self {
        Self::new(length).numeric()
    }

    /// Create with numeric digits, uppercase and lowercase
    /// roman letters.
    pub fn new_alpha_numeric(length: usize) -> Self {
        Self::new(length).upper().lower().numeric()
    }

    /// Options using printable ASCII characters.
    pub fn new_ascii_printable(length: usize) -> Self {
        Self::new(length)
            .upper()
            .lower()
            .numeric()
            .ascii_printable()
    }

    /// Create with diceware words.
    pub fn new_diceware(length: usize) -> Self {
        Self::new(length).diceware()
    }

    /// Length of the generated password.
    pub fn len(&self) -> usize {
        self.length
    }

    /// Determine if this generator is zero length.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Use lowercase roman letters.
    pub fn lower(mut self) -> Self {
        self.characters.push(ROMAN_LOWER);
        self
    }

    /// Use uppercase roman letters.
    pub fn upper(mut self) -> Self {
        self.characters.push(ROMAN_UPPER);
        self
    }

    /// Use numeric digits.
    pub fn numeric(mut self) -> Self {
        self.characters.push(DIGITS);
        self
    }

    /// Use printable ASCII punctuation characters.
    pub fn ascii_printable(mut self) -> Self {
        self.characters.push(PUNCTUATION);
        self
    }

    /// Use diceware words.
    pub fn diceware(mut self) -> Self {
        self.diceware = Some(default_config(self.len()));
        self
    }

    /// Generate a random password.
    pub fn one(&self) -> Result<PasswordResult> {
        let password = if let Some(config) = &self.diceware {
            let (passphrase, _) =
                generate_passphrase_config(config)?;
            passphrase
        } else {
            let rng = &mut rand::thread_rng();
            let len = self.characters.iter().fold(0, |acc, s| acc + s.len());
            let mut characters = Vec::with_capacity(len);
            for chars in &self.characters {
                let mut list = chars.chars().collect();
                characters.append(&mut list);
            }
            let mut password = String::new();
            for _ in 0..self.length {
                password.push(characters[rng.gen_range(0..len)]);
            }
            SecretString::new(password)
        };
        let entropy = zxcvbn(password.expose_secret(), &[])?;
        let result = PasswordResult { password, entropy };
        Ok(result)
    }

    /// Generate multiple passwords
    pub fn many(&self, count: usize) -> Result<Vec<PasswordResult>> {
        let mut results = Vec::new();
        for _ in 0..count {
            results.push(self.one()?);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;
    use secrecy::ExposeSecret;

    #[test]
    fn passgen_alpha() -> Result<()> {
        let generator = PasswordGen::new_alpha(12);
        let result = generator.one()?;
        assert_eq!(generator.len(), result.password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_numeric() -> Result<()> {
        let generator = PasswordGen::new_numeric(12);
        let result = generator.one()?;
        assert_eq!(generator.len(), result.password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_alphanumeric() -> Result<()> {
        let generator = PasswordGen::new_alpha_numeric(12);
        let result = generator.one()?;
        assert_eq!(generator.len(), result.password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_ascii_printable() -> Result<()> {
        let generator = PasswordGen::new_ascii_printable(12);
        let result = generator.one()?;
        assert_eq!(generator.len(), result.password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_ascii_printable_long() -> Result<()> {
        let generator = PasswordGen::new_ascii_printable(32);
        let result = generator.one()?;
        assert_eq!(generator.len(), result.password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_diceware() -> Result<()> {
        let generator = PasswordGen::new_diceware(6);
        let result = generator.one()?;
        let words: Vec<String> = result
            .password
            .expose_secret()
            .split(' ')
            .map(|s| s.to_owned())
            .collect();
        assert_eq!(generator.len(), words.len());
        Ok(())
    }

    #[test]
    fn passgen_generate() -> Result<()> {
        let generator = PasswordGen::new_ascii_printable(12);
        let count = 5;
        let passwords = generator.many(count)?;
        assert_eq!(count, passwords.len());
        for result in passwords {
            assert_eq!(
                generator.len(),
                result.password.expose_secret().len()
            );
        }
        Ok(())
    }
}
