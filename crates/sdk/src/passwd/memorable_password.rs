use rand::Rng;

const VOWELS: &[char] = &['a', 'e', 'i', 'o', 'u'];
const CONSONANTS: &[char] = &[
    'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm',
    'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'y', 'z'
];

pub fn generate_memorable_password() -> String {
    let mut rng = rand::thread_rng();
    let mut password = String::new();

    for i in 0..3 {
        if i > 0 {
            password.push('-');
        }
        
        for _ in 0..6 {
            if rng.gen_bool(0.4) {
                password.push(VOWELS[rng.gen_range(0..VOWELS.len())]);
            } else {
                password.push(CONSONANTS[rng.gen_range(0..CONSONANTS.len())]);
            }
        }
    }

    password
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_memorable_password() {
        let password = generate_memorable_password();
        assert_eq!(password.len(), 20);
        assert_eq!(password.matches('-').count(), 2);
        
        let parts: Vec<&str> = password.split('-').collect();
        assert_eq!(parts.len(), 3);
        for part in parts {
            assert_eq!(part.len(), 6);
        }
    }
}
