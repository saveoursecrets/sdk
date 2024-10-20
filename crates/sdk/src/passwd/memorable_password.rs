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
        for j in 0..6 {
            let char = if (j == 5 && i < 2 && rng.gen_bool(0.3))
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
            part.push(char);
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

            // Check for at least one digit
            assert!(password.chars().any(|c| c.is_ascii_digit()));

            // Check that the uppercase letter is at the start of one of the parts
            assert!(parts.iter().any(|part| part.chars().next().unwrap().is_ascii_uppercase()));

            // Check that the digit is at the end of any part or at the end of the password
            assert!(
                parts.iter().any(|part| part.chars().last().unwrap().is_ascii_digit())
                    || password.chars().last().unwrap().is_ascii_digit()
            );
        }
    }
}
