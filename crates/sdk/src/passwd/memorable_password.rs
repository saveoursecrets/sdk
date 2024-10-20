use rand::Rng;

const VOWELS: &[char] = &['a', 'e', 'i', 'o', 'u'];
const CONSONANTS: &[char] = &[
    'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r',
    's', 't', 'v', 'w', 'x', 'y', 'z',
];
const DIGITS: &[char] = &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

pub fn memorable_password() -> String {
    let mut rng = rand::thread_rng();
    let mut password = String::new();
    let mut digit_placed = false;
    let mut uppercase_placed = false;

    for i in 0..3 {
        if i > 0 {
            password.push('-');
        }

        let mut part = String::new();
        for j in 0..3 {
            let consonant = CONSONANTS[rng.gen_range(0..CONSONANTS.len())];
            let vowel = VOWELS[rng.gen_range(0..VOWELS.len())];
            
            if j == 2 && !digit_placed && (i == 2 || rng.gen_bool(0.3)) {
                // Place digit at the end of a part with 30% chance, or at the end if not placed yet
                digit_placed = true;
                part.push(consonant);
                part.push(vowel);
                part.push(DIGITS[rng.gen_range(0..DIGITS.len())]);
            } else {
                part.push(consonant);
                part.push(vowel);
            }
        }

        // Capitalize the first letter of a random part
        if !uppercase_placed && (i == 0 || rng.gen_bool(0.5)) {
            part = part[0..1].to_ascii_uppercase() + &part[1..];
            uppercase_placed = true;
        }

        password.push_str(&part);
    }

    // If no uppercase letter has been placed, capitalize the first letter of the last part
    if !uppercase_placed {
        let last_part_start = password.rfind('-').map(|i| i + 1).unwrap_or(0);
        password.replace_range(
            last_part_start..last_part_start + 1,
            &password[last_part_start..last_part_start + 1].to_ascii_uppercase(),
        );
    }

    // If no digit has been placed, replace the last character with a digit
    if !digit_placed {
        let last_char_index = password.len() - 1;
        password.replace_range(
            last_char_index..last_char_index + 1,
            &DIGITS[rng.gen_range(0..DIGITS.len())].to_string(),
        );
    }

    password
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memorable_password() {
        for _ in 0..100 {
            let password = memorable_password();
            println!("{}", password);
            assert_eq!(password.len(), 20);
            assert_eq!(password.matches('-').count(), 2);

            let parts: Vec<&str> = password.split('-').collect();
            assert_eq!(parts.len(), 3);
            for part in parts.iter() {
                assert_eq!(part.len(), 6);
            }

            // Check for exactly one uppercase letter
            assert_eq!(password.chars().filter(|c| c.is_ascii_uppercase()).count(), 1);

            // Check for exactly one digit
            assert_eq!(password.chars().filter(|c| c.is_ascii_digit()).count(), 1);

            // Check that the uppercase letter is at the start of one of the parts
            assert!(parts.iter().any(|part| part.chars().next().unwrap().is_ascii_uppercase()));

            // Check that each part follows the consonant-vowel pattern (except for the possible digit at the end)
            for part in parts.iter() {
                let chars: Vec<char> = part.chars().collect();
                assert!(CONSONANTS.contains(&chars[0].to_ascii_lowercase()));
                assert!(VOWELS.contains(&chars[1].to_ascii_lowercase()));
                assert!(CONSONANTS.contains(&chars[2].to_ascii_lowercase()));
                assert!(VOWELS.contains(&chars[3].to_ascii_lowercase()));
                assert!(CONSONANTS.contains(&chars[4].to_ascii_lowercase()));
                assert!(VOWELS.contains(&chars[5].to_ascii_lowercase()) || chars[5].is_ascii_digit());
            }
        }
    }
}
