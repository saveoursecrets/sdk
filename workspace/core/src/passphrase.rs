//! Utility to generate bip39 passphrase mnemonics.
//!
//! Word count must be 12, 18 or 24.
//!
use anyhow::{bail, Result};
use bip39::{Language, Mnemonic};
use std::str::FromStr;

/// Generate a bip39 mnemonic in the given language.
pub fn mnemonic_in(language: Language, word_count: WordCount) -> Result<Mnemonic> {
    let word_count: u16 = word_count.into();
    Ok(Mnemonic::generate_in(language, word_count as usize)?)
}

/// Generate bip39 passphrase words in the given language.
pub fn words_in(language: Language, word_count: WordCount) -> Result<String> {
    Ok(format!("{}", mnemonic_in(language, word_count)?))
}

/// Generate bip39 passphrase words in English.
pub fn words(word_count: WordCount) -> Result<String> {
    Ok(format!("{}", mnemonic_in(Language::English, word_count)?))
}

/// Variants for the number of words supported by
/// the BIP39 mnemonic generation algorithm.
#[derive(Debug)]
pub enum WordCount {
    /// Short number of words.
    Short(u16),
    /// Medium number of words.
    Medium(u16),
    /// Long number of words.
    Long(u16),
}

impl Default for WordCount {
    fn default() -> Self {
        Self::Short(12)
    }
}

impl Into<u16> for WordCount {
    fn into(self) -> u16 {
        match self {
            Self::Short(value) => value,
            Self::Medium(value) => value,
            Self::Long(value) => value,
        }
    }
}

impl FromStr for WordCount {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value: u16 = s.parse()?;
        WordCount::try_from(value)
    }
}

impl TryFrom<u16> for WordCount {
    type Error = anyhow::Error;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            12 => Ok(WordCount::Short(value)),
            18 => Ok(WordCount::Medium(value)),
            24 => Ok(WordCount::Long(value)),
            _ => bail!("word count must be 12, 18 or 24"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mnemonic_in;
    use anyhow::Result;
    use bip39::Language;

    #[test]
    fn generate_passphrase() -> Result<()> {
        let word_count = 12;
        let passphrase = mnemonic_in(Language::English, word_count)?;
        let words = format!("{}", passphrase);
        let items: Vec<&str> = words.split(" ").collect();
        assert_eq!(word_count, items.len());
        Ok(())
    }
}
