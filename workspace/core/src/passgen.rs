//! Utility for generating random passwords.

use crate::{Error, Result};
use rand::Rng;

const MIN_LENGTH: u8 = 8;

const ROMAN_LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const ROMAN_UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const PUNCTUATION: &str = "!\"#$%&'()*+,-./:;<=>?@`~\\]^_{}";

/// Options for password generation.
#[derive(Debug, Clone)]
pub struct PassGenOptions {
    length: u8,
    characters: Vec<&'static str>,
}

impl PassGenOptions {
    /// Options using uppercase and lowercase roman letters.
    pub fn new_alpha(length: u8) -> Self {
        Self {
            length,
            characters: vec![ROMAN_LOWER, ROMAN_UPPER],
        }
    }

    /// Options using numeric digits only.
    pub fn new_numeric(length: u8) -> Self {
        Self {
            length,
            characters: vec![DIGITS],
        }
    }

    /// Options using numeric digits, uppercase and lowercase
    /// roman letters.
    pub fn new_alpha_numeric(length: u8) -> Self {
        Self {
            length,
            characters: vec![ROMAN_LOWER, ROMAN_UPPER, DIGITS],
        }
    }

    /// Options using printable ASCII characters.
    pub fn new_ascii_printable(length: u8) -> Self {
        Self {
            length,
            characters: vec![ROMAN_LOWER, ROMAN_UPPER, DIGITS, PUNCTUATION],
        }
    }
}

/// Generate a random password.
pub fn generate_password(options: PassGenOptions) -> Result<String> {
    if options.length < MIN_LENGTH {
        return Err(Error::PasswordLength(MIN_LENGTH));
    }

    let rng = &mut rand::thread_rng();
    let len = options.characters.iter().fold(0, |acc, s| acc + s.len());
    let mut characters = Vec::with_capacity(len);
    for chars in options.characters {
        let mut list = chars.chars().collect();
        characters.append(&mut list);
    }
    let mut password = String::new();
    for _ in 0..options.length {
        password.push(characters[rng.gen_range(0..len)]);
    }
    Ok(password)
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;

    #[test]
    fn passgen_invalid_length() -> Result<()> {
        let options = PassGenOptions::new_alpha(2);
        assert!(generate_password(options).is_err());
        Ok(())
    }

    #[test]
    fn passgen_alpha() -> Result<()> {
        let options = PassGenOptions::new_alpha(12);
        let password = generate_password(options.clone())?;
        assert_eq!(options.length as usize, password.len());
        Ok(())
    }

    #[test]
    fn passgen_numeric() -> Result<()> {
        let options = PassGenOptions::new_numeric(12);
        let password = generate_password(options.clone())?;
        assert_eq!(options.length as usize, password.len());
        Ok(())
    }

    #[test]
    fn passgen_alphanumeric() -> Result<()> {
        let options = PassGenOptions::new_alpha_numeric(12);
        let password = generate_password(options.clone())?;
        assert_eq!(options.length as usize, password.len());
        Ok(())
    }

    #[test]
    fn passgen_ascii_printable() -> Result<()> {
        let options = PassGenOptions::new_ascii_printable(12);
        let password = generate_password(options.clone())?;
        assert_eq!(options.length as usize, password.len());
        Ok(())
    }
}
