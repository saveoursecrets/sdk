//! Utility for generating random passwords.
use crate::{Error, Result};
use secrecy::SecretString;

use passwords::{analyzer, scorer, PasswordGenerator};

/// Options for password generation.
#[derive(Debug, Clone)]
pub struct PasswordGen {
    inner: PasswordGenerator,
}

impl PasswordGen {
    /// Get the character length of the generated password.
    pub fn len(&self) -> usize {
        self.inner.length
    }

    /// Determine if this generator is zero length.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Options using uppercase and lowercase roman letters.
    pub fn new_alpha(length: usize) -> Self {
        Self {
            inner: PasswordGenerator::new()
                .length(length)
                .lowercase_letters(true)
                .uppercase_letters(true)
                .symbols(false),
        }
    }

    /// Options using numeric digits only.
    pub fn new_numeric(length: usize) -> Self {
        Self {
            inner: PasswordGenerator::new()
                .length(length)
                .numbers(true)
                .lowercase_letters(false)
                .uppercase_letters(false)
                .symbols(false),
        }
    }

    /// Options using numeric digits, uppercase and lowercase
    /// roman letters.
    pub fn new_alpha_numeric(length: usize) -> Self {
        Self {
            inner: PasswordGenerator::new()
                .length(length)
                .numbers(true)
                .lowercase_letters(true)
                .uppercase_letters(true)
                .exclude_similar_characters(true),
        }
    }

    /// Options using printable ASCII characters.
    pub fn new_ascii_printable(length: usize) -> Self {
        Self {
            inner: PasswordGenerator::new()
                .length(length)
                .numbers(true)
                .symbols(true)
                .lowercase_letters(true)
                .uppercase_letters(true)
                .exclude_similar_characters(true),
        }
    }
}

/// Generate a single random password.
pub fn generate_one(options: PasswordGen) -> Result<(SecretString, f64)> {
    let password = options
        .inner
        .generate_one()
        .map_err(|e| Error::PasswordGenerator(e.to_owned()))?;

    let score = scorer::score(&analyzer::analyze(&password));

    Ok((SecretString::new(password), score))
}

/// Generate multiple random passwords.
pub fn generate(
    options: PasswordGen,
    count: usize,
) -> Result<Vec<(SecretString, f64)>> {
    let passwords = options
        .inner
        .generate(count)
        .map_err(|e| Error::PasswordGenerator(e.to_owned()))?;
    Ok(passwords
        .into_iter()
        .map(|password| {
            let score = scorer::score(&analyzer::analyze(&password));
            (SecretString::new(password), score)
        })
        .collect())
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;
    use secrecy::ExposeSecret;

    #[test]
    fn passgen_alpha() -> Result<()> {
        let options = PasswordGen::new_alpha(12);
        let (password, _) = generate_one(options.clone())?;
        assert_eq!(options.len(), password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_numeric() -> Result<()> {
        let options = PasswordGen::new_numeric(12);
        let (password, _) = generate_one(options.clone())?;
        assert_eq!(options.len(), password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_alphanumeric() -> Result<()> {
        let options = PasswordGen::new_alpha_numeric(12);
        let (password, _) = generate_one(options.clone())?;
        assert_eq!(options.len(), password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_ascii_printable() -> Result<()> {
        let options = PasswordGen::new_ascii_printable(12);
        let (password, _) = generate_one(options.clone())?;
        assert_eq!(options.len(), password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_ascii_printable_long() -> Result<()> {
        let options = PasswordGen::new_ascii_printable(32);
        let (password, _) = generate_one(options.clone())?;
        assert_eq!(options.len(), password.expose_secret().len());
        Ok(())
    }

    #[test]
    fn passgen_generate() -> Result<()> {
        let options = PasswordGen::new_ascii_printable(12);
        let count = 5;
        let passwords = generate(options.clone(), count)?;
        assert_eq!(count, passwords.len());
        for (password, _) in passwords {
            assert_eq!(options.len(), password.expose_secret().len());
        }
        Ok(())
    }
}
