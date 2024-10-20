//! Utility for generating random passwords.
use chbs::{config::BasicConfig, word::WordSampler};
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use zxcvbn::{zxcvbn, Entropy};

use crate::{crypto::csprng, Result};

const ROMAN_LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const ROMAN_UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const PUNCTUATION: &str = "!\"#$%&'()*+,-./:;<=>?@`~\\]^_{}";

use super::{diceware, memorable::memorable_password};

/// Measure the entropy in a password.
pub fn measure_entropy(password: &str, user_inputs: &[&str]) -> Entropy {
    zxcvbn(password, user_inputs)
}

/// Generate a password.
pub fn generate_one(kind: &PasswordType) -> Result<PasswordResult> {
    let builder = PasswordBuilder::new(kind);
    builder.one()
}

/// Generate multiple passwords.
pub fn generate_many(
    kind: &PasswordType,
    count: usize,
) -> Result<Vec<PasswordResult>> {
    let builder = PasswordBuilder::new(kind);
    builder.many(count)
}

/// Type of passwords that can be generated.
#[derive(Debug)]
pub enum PasswordType {
    /// Apple-style memorable and easy to type password.
    Memorable {
        /// Number of words.
        words: usize,
    },
    /// Alpha ASCII password.
    Alpha {
        /// Number of characters.
        characters: usize,
    },
    /// Alphanumeric ASCII password.
    AlphaNumeric {
        /// Number of characters.
        characters: usize,
    },
    /// Numeric password.
    Numeric {
        /// Number of digits.
        digits: usize,
    },
    /// Random ASCII printable password.
    Random {
        /// Number of characters.
        length: usize,
    },
    /// Diceware password.
    Diceware {
        /// Number of words.
        words: usize,
    },
}

impl Default for PasswordType {
    fn default() -> Self {
        Self::Memorable { words: 3 }
    }
}

/// Generated password result.
#[derive(Debug, Clone)]
pub struct PasswordResult {
    /// Generated password.
    pub password: SecretString,
    /// Computed entropy for the password.
    pub entropy: Entropy,
}

/// Builder for password generation.
#[derive(Debug, Clone)]
struct PasswordBuilder {
    length: usize,
    memorable: bool,
    characters: Vec<&'static str>,
    diceware: Option<BasicConfig<WordSampler>>,
}

impl PasswordBuilder {
    /// Create a new password generator.
    pub fn new(kind: &PasswordType) -> Self {
        match kind {
            PasswordType::Memorable { words } => {
                PasswordBuilder::new_memorable(*words)
            }
            PasswordType::Alpha { characters } => {
                PasswordBuilder::new_alpha(*characters)
            }
            PasswordType::AlphaNumeric { characters } => {
                PasswordBuilder::new_alpha_numeric(*characters)
            }
            PasswordType::Numeric { digits } => {
                PasswordBuilder::new_numeric(*digits)
            }
            PasswordType::Random { length } => {
                PasswordBuilder::new_ascii_printable(*length)
            }
            PasswordType::Diceware { words } => {
                PasswordBuilder::new_diceware(*words)
            }
        }
    }

    /// Create a password generator with a length.
    fn new_length(length: usize) -> Self {
        Self {
            length,
            memorable: false,
            characters: vec![],
            diceware: None,
        }
    }

    /// Create memorable password.
    pub fn new_memorable(length: usize) -> Self {
        Self::new_length(length).memorable()
    }

    /// Create with lowercase and uppercase character sets.
    pub fn new_alpha(length: usize) -> Self {
        Self::new_length(length).upper().lower()
    }

    /// Create with numeric digits only.
    pub fn new_numeric(length: usize) -> Self {
        Self::new_length(length).numeric()
    }

    /// Create with numeric digits, uppercase and lowercase
    /// roman letters.
    pub fn new_alpha_numeric(length: usize) -> Self {
        Self::new_length(length).upper().lower().numeric()
    }

    /// Options using printable ASCII characters.
    pub fn new_ascii_printable(length: usize) -> Self {
        Self::new_length(length)
            .upper()
            .lower()
            .numeric()
            .ascii_printable()
    }

    /// Create with diceware words.
    pub fn new_diceware(length: usize) -> Self {
        Self::new_length(length).diceware()
    }

    /// Length of the generated password.
    pub fn len(&self) -> usize {
        self.length
    }

    /*
    /// Determine if this generator is zero length.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    */

    /// Use memorable strategy.
    pub fn memorable(mut self) -> Self {
        self.memorable = true;
        self
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
        self.diceware = Some(diceware::default_config(self.len()));
        self
    }

    /// Generate a random password.
    pub fn one(&self) -> Result<PasswordResult> {
        let password = if let Some(config) = &self.diceware {
            let (passphrase, _) =
                diceware::generate_passphrase_config(config)?;
            passphrase
        } else if self.memorable {
            SecretString::new(memorable_password(self.length))
        } else {
            let rng = &mut csprng();
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
        let entropy = zxcvbn(password.expose_secret(), &[]);
        Ok(PasswordResult { password, entropy })
    }

    /// Generate multiple passwords
    pub fn many(&self, count: usize) -> Result<Vec<PasswordResult>> {
        let mut results = Vec::with_capacity(count);
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
    fn passgen_memorable() -> Result<()> {
        let generator = PasswordBuilder::new_memorable(3);
        let result = generator.one()?;
        assert_eq!(20, result.password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_alpha() -> Result<()> {
        let generator = PasswordBuilder::new_alpha(12);
        let result = generator.one()?;
        assert_eq!(generator.len(), result.password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_numeric() -> Result<()> {
        let generator = PasswordBuilder::new_numeric(12);
        let result = generator.one()?;
        assert_eq!(generator.len(), result.password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_alphanumeric() -> Result<()> {
        let generator = PasswordBuilder::new_alpha_numeric(12);
        let result = generator.one()?;
        assert_eq!(generator.len(), result.password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_ascii_printable() -> Result<()> {
        let generator = PasswordBuilder::new_ascii_printable(12);
        let result = generator.one()?;
        assert_eq!(generator.len(), result.password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_ascii_printable_long() -> Result<()> {
        let generator = PasswordBuilder::new_ascii_printable(32);
        let result = generator.one()?;
        assert_eq!(generator.len(), result.password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_diceware() -> Result<()> {
        let generator = PasswordBuilder::new_diceware(6);
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
        let generator = PasswordBuilder::new_ascii_printable(12);
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
