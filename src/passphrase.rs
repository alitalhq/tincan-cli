//! Generated passphrases, and a warning for typed ones.
//!
//! A room opened by name is only as private as its passphrase: anyone can compute the
//! key for a guessed name and passphrase and look it up. So `tincan host lobby` makes one
//! up instead of trusting whoever is at the keyboard to — four words out of 2048, about
//! 44 bits, which Argon2id puts out of brute-force reach, and short enough to say aloud.

use rand::Rng;

/// The BIP-39 English word list (MIT). Every word is 3–8 letters and no two share their
/// first four, which is what makes them hard to mishear.
const WORDLIST: &str = include_str!("bip39-english.txt");
/// How many words a generated passphrase has.
const WORDS: usize = 4;
/// Below this length a typed passphrase earns a warning, unless it is made of words.
const COMFORTABLE_CHARS: usize = 16;

/// Makes up a passphrase: `chestnut-ferry-lens-moss`.
pub fn generate() -> String {
    let words: Vec<&str> = WORDLIST.lines().collect();
    let mut rng = rand::rng();
    (0..WORDS)
        .map(|_| {
            let mut bytes = [0u8; 2];
            rng.fill_bytes(&mut bytes);
            // 2048 is 2^11, so the mask picks a word with no bias.
            words[(u16::from_le_bytes(bytes) & 0x07ff) as usize]
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// Whether a passphrase someone typed is too easy to guess.
///
/// Deliberately rough: it catches "123456" and "secret" and does not pretend to measure
/// entropy. A generated passphrase never goes through here.
pub fn is_weak(passphrase: &str) -> bool {
    let words = passphrase
        .split(|c: char| c.is_whitespace() || c == '-' || c == '_')
        .filter(|word| word.chars().count() >= 3)
        .count();
    passphrase.trim().chars().count() < COMFORTABLE_CHARS && words < WORDS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn the_wordlist_is_whole() {
        let words: Vec<&str> = WORDLIST.lines().collect();
        assert_eq!(
            words.len(),
            2048,
            "the index mask assumes exactly 2^11 words"
        );
        assert_eq!(
            words.iter().collect::<HashSet<_>>().len(),
            2048,
            "words must be unique"
        );
        assert!(
            words
                .iter()
                .all(|w| w.chars().all(|c| c.is_ascii_lowercase()))
        );
    }

    #[test]
    fn generated_passphrases_are_four_listed_words() {
        let listed: HashSet<&str> = WORDLIST.lines().collect();
        let passphrase = generate();
        let words: Vec<&str> = passphrase.split('-').collect();
        assert_eq!(words.len(), WORDS, "{passphrase}");
        assert!(words.iter().all(|w| listed.contains(w)), "{passphrase}");
    }

    #[test]
    fn generated_passphrases_differ() {
        let seen: HashSet<String> = (0..20).map(|_| generate()).collect();
        assert!(seen.len() > 1, "the generator keeps saying the same thing");
    }

    #[test]
    fn short_typed_passwords_are_weak() {
        assert!(is_weak("123456"));
        assert!(is_weak("secret"));
        assert!(is_weak("hunter2-x"));
        assert!(!is_weak("chestnut-ferry-lens-moss"));
        assert!(
            !is_weak("act add ago aim"),
            "four short words are still four words"
        );
        assert!(!is_weak("a-long-enough-password"));
    }
}
