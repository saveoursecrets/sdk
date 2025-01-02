use sos_password::{memorable_password, CONSONANTS, VOWELS};

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
