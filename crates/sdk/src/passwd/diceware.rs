//! Helper functions for generating diceware passwords.
use crate::{Error, Result};
use chbs::{
    config::{BasicConfig, BasicConfigBuilder},
    prelude::*,
    probability::Probability,
    word::{WordList, WordSampler},
};
use secrecy::{Secret, SecretString};

use once_cell::sync::Lazy;

static WORD_LIST: Lazy<WordList> = Lazy::new(WordList::builtin_eff_large);

/// Generate a passphrase using the given config.
pub fn generate_passphrase_config(
    config: &BasicConfig<WordSampler>,
) -> Result<(SecretString, f64)> {
    if config.words < 6 {
        return Err(Error::DicewareWordsTooFew(config.words, 6));
    }

    let scheme = config.to_scheme();
    Ok((Secret::new(scheme.generate()), scheme.entropy().bits()))
}

/// Generate a diceware passphrase with the given number of words.
///
/// The number of words must be at least six.
pub fn generate_passphrase_words(
    words: usize,
) -> Result<(SecretString, f64)> {
    let config = default_config(words);
    generate_passphrase_config(&config)
}

/// Generate a diceware passphrase with six words which is ~171 bits of entropy.
pub fn generate_passphrase() -> Result<(SecretString, f64)> {
    generate_passphrase_words(6)
}

/// Get the default config for diceware passphrase generation.
pub fn default_config(words: usize) -> BasicConfig<WordSampler> {
    let config = BasicConfigBuilder::default()
        .word_provider(WORD_LIST.sampler())
        .words(words)
        .separator(' ')
        .capitalize_first(Probability::Never)
        .capitalize_words(Probability::Never)
        .build()
        .unwrap();
    config
}
