use crate::{CONSONANTS, DIGITS, VOWELS};
use rand::rngs::OsRng;
use rand::Rng;

/// Memorable password generator.
pub fn memorable_password(num_words: usize) -> String {
    let rng = &mut OsRng;
    let num_syllables = num_words * 2;
    let mut words = Vec::with_capacity(num_words);
    let mut syllables = Vec::with_capacity(num_syllables);

    for _ in 0..num_syllables {
        let mut syllable = String::new();
        let vowel = VOWELS[rng.gen_range(0..VOWELS.len())];
        syllable.push(CONSONANTS[rng.gen_range(0..CONSONANTS.len())]);
        syllable.push(vowel);
        syllable.push(CONSONANTS[rng.gen_range(0..CONSONANTS.len())]);
        syllables.push(syllable);
    }

    let digit_word = rng.gen_range(0..=2);
    let upper_word = rng.gen_range(0..=2);

    for (index, chunks) in syllables.chunks_exact(2).enumerate() {
        let mut word = String::new();
        word.push_str(chunks.first().unwrap());
        word.push_str(chunks.last().unwrap());

        if index == digit_word {
            let digit = DIGITS[rng.gen_range(0..DIGITS.len())].to_string();
            // Avoid starting the first word with a digit
            // or colliding with an uppercase character
            if index == 0 || digit_word == upper_word {
                word.replace_range(5..6, &digit);
            } else if rng.gen_bool(0.5) {
                word.replace_range(0..1, &digit);
            } else {
                word.replace_range(5..6, &digit);
            }
        }

        // Capitalize the first letter
        if index == upper_word {
            word = word[0..1].to_ascii_uppercase() + &word[1..];
        }

        words.push(word);
    }

    words.join("-")
}
