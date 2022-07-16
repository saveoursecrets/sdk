//! Diceware helper functions for generating passphrases.
use crate::{Error, Result};
use chbs::{
    config::{BasicConfig, BasicConfigBuilder},
    prelude::*,
    probability::Probability,
    word::{WordList, WordSampler},
};
use secrecy::{Secret, SecretString};

/// Generate a passphrase using the given config.
fn generate_passphrase_config(
    config: Option<BasicConfig<WordSampler>>,
) -> Result<(SecretString, f64)> {
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
    Ok((Secret::new(scheme.generate()), scheme.entropy().bits()))
}

/// Generate a diceware passphrase with the given number of words.
///
/// The number of words must be at least six.
pub fn generate_passphrase_words(words: u8) -> Result<(SecretString, f64)> {
    let config = default_config(words as usize);
    generate_passphrase_config(Some(config))
}

/// Generate a diceware passphrase with six words which is ~171 bits of entropy.
pub fn generate_passphrase() -> Result<(SecretString, f64)> {
    generate_passphrase_words(6)
}

/// Get the default config for diceware passphrase generation.
fn default_config(words: usize) -> BasicConfig<WordSampler> {
    let list = WordList::builtin_eff_large();
    let config = BasicConfigBuilder::default()
        .word_provider(list.sampler())
        .words(words)
        .separator(' ')
        .capitalize_first(Probability::Never)
        .capitalize_words(Probability::Never)
        .build()
        .unwrap();
    config
}
