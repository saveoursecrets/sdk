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

    for i in 0..3 {
        if i > 0 {
            password.push('-');
        }

        for j in 0..6 {
            let char = if j == 0 && i == 0 {
                // Ensure first character is uppercase
                CONSONANTS[rng.gen_range(0..CONSONANTS.len())]
                    .to_ascii_uppercase()
            } else if (j == 5 && i < 2 && rng.gen_bool(0.3))
                || (j == 5 && i == 2 && !digit_placed)
            {
                // Place digit at the end of first two parts with 30% chance, or at the end if not placed yet
                digit_placed = true;
                DIGITS[rng.gen_range(0..DIGITS.len())]
            } else if rng.gen_bool(0.4) {
                VOWELS[rng.gen_range(0..VOWELS.len())]
            } else {
                CONSONANTS[rng.gen_range(0..CONSONANTS.len())]
            };
            password.push(char);
        }
    }

    // Randomly capitalize one more character
    let uppercase_index = rng.gen_range(1..password.len());
    password.replace_range(
        uppercase_index..=uppercase_index,
        &password[uppercase_index..=uppercase_index].to_ascii_uppercase(),
    );

    password
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_memorable_password() {
        for _ in 0..10 {
            let password = memorable_password();
            println!("{:#?}", password);
            assert_eq!(password.len(), 20);
            assert_eq!(password.matches('-').count(), 2);

            let parts: Vec<&str> = password.split('-').collect();
            assert_eq!(parts.len(), 3);
            for part in parts {
                assert_eq!(part.len(), 6);
            }

            // Check for at least one uppercase letter
            assert!(password.chars().any(|c| c.is_ascii_uppercase()));

            // Check for at least one digit
            assert!(password.chars().any(|c| c.is_ascii_digit()));

            // Check that the first character is uppercase
            assert!(password.chars().next().unwrap().is_ascii_uppercase());

            // Check that the digit is at the end of any part or at the end of the password
            assert!(
                parts.iter().any(|part| part
                    .chars()
                    .last()
                    .unwrap()
                    .is_ascii_digit())
                    || password.chars().last().unwrap().is_ascii_digit()
            );
        }
    }
}
