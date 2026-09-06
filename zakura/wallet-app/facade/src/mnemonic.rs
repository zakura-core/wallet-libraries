//! Seed phrases.
//!
//! This lives in Rust so that no other language in the stack ever holds
//! entropy or a seed phrase: an application asks for a phrase, shows it, and
//! hands it back to be turned into a seed. The seed itself is never stored by
//! the wallet — see [`crate::keys`] — so this is the only place it is made.

use bip0039::{Count, English, Mnemonic};
use zeroize::Zeroizing;

use crate::error::Error;

/// Generates a new 24-word seed phrase.
///
/// Twenty-four words rather than twelve: the phrase is written down once and
/// used for years, and the extra entropy costs the user nothing they will
/// notice.
pub fn generate() -> Zeroizing<String> {
    Zeroizing::new(Mnemonic::<English>::generate(Count::Words24).into_phrase())
}

/// Returns whether a phrase is a valid mnemonic.
pub fn validate(phrase: &str) -> bool {
    Mnemonic::<English>::from_phrase(phrase).is_ok()
}

/// Turns a seed phrase into the seed the wallet derives accounts from.
///
/// The passphrase is the BIP 39 one, empty for an ordinary wallet.
pub fn to_seed(phrase: &str, passphrase: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mnemonic = Mnemonic::<English>::from_phrase(phrase)
        .map_err(|e| Error::BadMnemonic(e.to_string()))?;
    Ok(Zeroizing::new(
        mnemonic.to_seed(passphrase).as_slice().to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_phrase_is_twenty_four_words_and_valid() {
        let phrase = generate();
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert!(validate(&phrase));
    }

    #[test]
    fn two_generated_phrases_differ() {
        assert_ne!(*generate(), *generate());
    }

    #[test]
    fn a_phrase_derives_the_same_seed_every_time() {
        let phrase = generate();
        assert_eq!(
            *to_seed(&phrase, "").unwrap(),
            *to_seed(&phrase, "").unwrap()
        );
    }

    /// The passphrase is part of the derivation, not a decoration: the same
    /// words with a different passphrase are a different wallet, which is the
    /// whole point and also the way somebody loses their money.
    #[test]
    fn the_passphrase_changes_the_seed() {
        let phrase = generate();
        assert_ne!(
            *to_seed(&phrase, "").unwrap(),
            *to_seed(&phrase, "hunter2").unwrap()
        );
    }

    #[test]
    fn a_seed_is_sixty_four_bytes() {
        assert_eq!(to_seed(&generate(), "").unwrap().len(), 64);
    }

    #[test]
    fn nonsense_is_refused() {
        assert!(!validate("not a seed phrase at all"));
        assert!(to_seed("not a seed phrase at all", "").is_err());
    }

    /// A mnemonic carries a checksum, so a single wrong word is detectable and
    /// must be reported rather than silently deriving a different wallet.
    #[test]
    fn one_wrong_word_fails_the_checksum() {
        let phrase = generate();
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        // "zoo" is in the wordlist, so this fails on the checksum rather than
        // on an unknown word.
        let replaced = if words[0] == "zoo" { "abandon" } else { "zoo" };
        words[0] = replaced;
        assert!(!validate(&words.join(" ")));
    }
}
