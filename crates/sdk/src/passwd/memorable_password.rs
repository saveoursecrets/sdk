use rand::rngs::OsRng;
use rand::Rng;

const VOWELS: &[char] = &['a', 'e', 'i', 'o', 'u'];
const CONSONANTS: &[char] = &[
    'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r',
    's', 't', 'v', 'w', 'x', 'y', 'z',
];
const DIGITS: &[char] = &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

pub fn memorable_password(num_words: usize) -> String {
    let rng = &mut OsRng;
    let num_syllables = num_words * 2;

    let mut words = Vec::with_capacity(num_words);
    let mut syllables = Vec::with_capacity(num_syllables);

    for _ in 0..6 {
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
            } else {
                if rng.gen_bool(0.5) {
                    word.replace_range(0..1, &digit);
                } else {
                    word.replace_range(5..6, &digit);
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memorable_password() {
        for _ in 0..100 {
            let password = memorable_password(3);
            println!("{}", password);

            assert_eq!(password.len(), 20);
            assert_eq!(password.matches('-').count(), 2);

            let parts: Vec<&str> = password.split('-').collect();
            assert_eq!(parts.len(), 3);
            for part in parts.iter() {
                assert_eq!(part.len(), 6);
            }

            // Check for exactly one uppercase letter
            assert_eq!(
                password.chars().filter(|c| c.is_ascii_uppercase()).count(),
                1
            );

            // Check for exactly one digit
            assert_eq!(
                password.chars().filter(|c| c.is_ascii_digit()).count(),
                1
            );

            // Check that the uppercase letter is at the start of one of the parts
            assert!(parts.iter().any(|part| part
                .chars()
                .next()
                .unwrap()
                .is_ascii_uppercase()));

            fn is_consonant(c: &char, allow_digit: bool) -> bool {
                CONSONANTS.contains(&c.to_ascii_lowercase())
                    || (allow_digit && c.is_ascii_digit())
            }

            fn is_vowel(c: &char) -> bool {
                VOWELS.contains(&c.to_ascii_lowercase())
            }

            // Check that each part follows the consonant-vowel pattern (except for the possible digit at the end)
            for (index, part) in parts.iter().enumerate() {
                let chars: Vec<char> = part.chars().collect();

                assert!(is_consonant(&chars[0], index > 0));
                assert!(is_vowel(&chars[1]));
                assert!(is_consonant(&chars[2], false));

                assert!(is_consonant(&chars[3], false));
                assert!(is_vowel(&chars[4]));
                assert!(is_consonant(&chars[5], true));
            }
        }
    }
}
