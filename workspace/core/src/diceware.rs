//! Diceware helper functions for generating passphrases.
use crate::{Error, Result};
use chbs::{config::BasicConfig, prelude::*, probability::Probability, word::WordSampler};

/// Generate a passphrase and the entropy in bits.
pub fn generate_passphrase(config: Option<BasicConfig<WordSampler>>) -> Result<(String, f64)> {
    let config = if let Some(config) = config {
        config
    } else {
        // Lowercase with 6 words gets us about 77 bits of entropy
        default_config(6)
    };

    if config.words < 6 {
        return Err(Error::DicewareWordsTooFew(config.words, 6));
    }

    let scheme = config.to_scheme();
    Ok((scheme.generate(), scheme.entropy().bits()))
}

/// Generate a passphrase with the given number of words.
///
/// The number of words must be at least six.
pub fn generate_passphrase_words(words: u8) -> Result<(String, f64)> {
    let config = default_config(words as usize);
    generate_passphrase(Some(config))
}

/// Get the default config for diceware passphrase generation.
fn default_config(words: usize) -> BasicConfig<WordSampler> {
    let mut config = BasicConfig::default();
    config.words = words;
    config.separator = " ".into();
    config.capitalize_first = Probability::Never;
    config.capitalize_words = Probability::Never;
    config
}
