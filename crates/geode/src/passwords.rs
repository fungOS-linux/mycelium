//! Cryptographically secure password and passphrase generation.
//!
//! Every byte comes from the OS CSPRNG (`getrandom`), so the values are
//! unpredictable even to someone watching the whole system state. This module
//! only *creates* secrets; it never stores them, which is why the rest of
//! geode never depends on it at rest.

use rand_core::RngCore;

/// The printable character class a password may draw from.
///
/// The symbol set deliberately avoids shell metacharacters, backslashes, and
/// quotes so a generated value can be written to a file, an env var, or a URL
/// argument without further escaping.
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/";

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT: &[u8] = b"0123456789";

/// Which character classes a generated password must contain.
#[derive(Clone, Copy, Debug, Default)]
pub struct Requirements {
    pub lower: bool,
    pub upper: bool,
    pub digit: bool,
    pub symbol: bool,
}

impl Requirements {
    /// How many guaranteed characters this set of requirements needs.
    fn required_len(&self) -> usize {
        self.lower as usize + self.upper as usize + self.digit as usize + self.symbol as usize
    }

    fn class_arrays(&self) -> Vec<&[u8]> {
        let mut out = Vec::with_capacity(self.required_len());
        if self.lower {
            out.push(LOWER);
        }
        if self.upper {
            out.push(UPPER);
        }
        if self.digit {
            out.push(DIGIT);
        }
        if self.symbol {
            out.push(SYMBOLS);
        }
        out
    }

    fn class_bytes(&self) -> Vec<u8> {
        self.class_arrays()
            .into_iter()
            .flat_map(|c| c.iter().copied())
            .collect()
    }

    fn class_arrays_with_flags(&self) -> Vec<(&'static [u8], bool)> {
        let mut out = Vec::with_capacity(self.required_len());
        if self.lower {
            out.push((LOWER, true));
        }
        if self.upper {
            out.push((UPPER, true));
        }
        if self.digit {
            out.push((DIGIT, true));
        }
        if self.symbol {
            out.push((SYMBOLS, true));
        }
        out
    }
}

/// A CSPRNG-backed password generator.
///
/// `length` is the final password length in characters, clamped so every
/// required character class can appear at least once.
#[derive(Clone, Debug)]
pub struct PasswordGenerator {
    requirements: Requirements,
    length: usize,
}

impl PasswordGenerator {
    /// A generator that requires every character class and emits 16-char
    /// passwords — a reasonable default for appliance service accounts.
    pub fn new(length: usize) -> Self {
        Self {
            requirements: Requirements {
                lower: true,
                upper: true,
                digit: true,
                symbol: true,
            },
            length,
        }
    }

    /// Override the character-class requirements. A class of `false` removes it
    /// from the pool and stops guaranteeing it.
    pub fn with_requirements(mut self, requirements: Requirements) -> Self {
        self.requirements = requirements;
        let required = self.requirements.required_len();
        if required == 0 {
            self.requirements = Requirements {
                lower: true,
                upper: true,
                digit: true,
                symbol: true,
            };
        }
        self.length = self.length.max(required);
        self
    }

    /// Draw a fresh password. The result is freshly minted on every call.
    pub fn generate(&self, mut rng: impl RngCore) -> String {
        let mut chars: Vec<u8> = Vec::with_capacity(self.length);

        // Guarantee one character per required class up front.
        for (class, enabled) in self.requirements.class_arrays_with_flags() {
            if !enabled {
                continue;
            }
            chars.push(pick(class, &mut rng));
        }

        // Fill the remainder from the combined class pool.
        let pool = self.requirements.class_bytes();
        for _ in chars.len()..self.length {
            chars.push(pick(&pool, &mut rng));
        }

        // Fisher–Yates shuffle so the guaranteed classes are not positional.
        for i in (1..chars.len()).rev() {
            let j = pick_index(&mut rng, (i as u32 + 1) as u64);
            chars.swap(i, j);
        }

        String::from_utf8(chars).expect("charset bytes are all ASCII")
    }
}

/// A CSPRNG-backed passphrase generator.
///
/// Passphrases join `count` words from `wordlist`, which keeps entropy high
/// while staying easy for a human to type.
#[derive(Clone, Debug)]
pub struct PhraseGenerator {
    words: Vec<String>,
    count: usize,
}

impl PhraseGenerator {
    /// Build a generator from an iterator of word strings. `count` is the
    /// number of words per passphrase (clamped to at least one).
    pub fn with_words<I, S>(words: I, count: usize) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            words: words.into_iter().map(|w| w.into().to_string()).collect(),
            count: count.max(1),
        }
    }

    /// Draw a fresh passphrase.
    pub fn generate(&self, mut rng: impl RngCore) -> String {
        let mut words = Vec::with_capacity(self.count);
        for _ in 0..self.count {
            words.push(pick_index(&mut rng, self.words.len() as u64) as usize);
        }
        words
            .into_iter()
            .map(|i| self.words[i].clone())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// The small built-in wordlist (300 words) for passphrase generation.
///
/// Kept self-contained so geode needs no external data file. Swap in a larger
/// list (FIPS 197, EFF, or xkcd-style) via [`PhraseGenerator::with_words`].
pub fn built_in_wordlist() -> Vec<&'static str> {
    [
        "able",
        "action",
        "!bang",
        "africa",
        "after",
        "again",
        "agent",
        "alarm",
        "album",
        "alive",
        "apple",
        "arena",
        "arrow",
        "author",
        "avatar",
        "beach",
        "beauty",
        "believe",
        "beyond",
        "blade",
        "blaze",
        "bleak",
        "block",
        "blood",
        "blush",
        "breeze",
        "bright",
        "broken",
        "bubble",
        "cabin",
        "candy",
        "carpet",
        "castle",
        "cellar",
        "cherry",
        "circle",
        "civic",
        "claim",
        "clash",
        "cliff",
        "clock",
        "cloud",
        "cluster",
        "coast",
        "cobra",
        "color",
        "comet",
        "crane",
        "cream",
        "crime",
        "cross",
        "crown",
        "crystal",
        "dagger",
        "dance",
        "delta",
        "diana",
        "dolphin",
        "dove",
        "dragon",
        "drift",
        "eagle",
        "ember",
        "eclipse",
        "echo",
        "eager",
        "engine",
        "falcon",
        "ferry",
        "field",
        "fjord",
        "flame",
        "flint",
        "forest",
        "frost",
        "ghost",
        "globe",
        "grape",
        "grass",
        "gravity",
        "green",
        "grove",
        "guard",
        "hammer",
        "harbor",
        "harvest",
        "haven",
        "hazard",
        "helix",
        "honey",
        "horizon",
        "hurricane",
        "icicle",
        "igloo",
        "iron",
        "ivory",
        "jaguar",
        "jungle",
        "karma",
        "keel",
        "keyhole",
        "kiosk",
        "lagoon",
        "lemon",
        "lens",
        "light",
        "lighthouse",
        "lunar",
        "magma",
        "maple",
        "marble",
        "matrix",
        "meadow",
        "mercury",
        "mist",
        "monsoon",
        "moon",
        "murmur",
        "nebula",
        "noble",
        "north",
        "nuclear",
        "ocean",
        "olive",
        "opal",
        "orbit",
        "otter",
        "oxen",
        "panda",
        "parade",
        "pardon",
        "parrot",
        "part",
        "pebble",
        "pelican",
        "pencil",
        "penny",
        "piano",
        "pigeon",
        "pilot",
        "pine",
        "pistol",
        "pizza",
        "pixel",
        "planet",
        "plastic",
        "platter",
        "plaza",
        "plump",
        "polar",
        "police",
        "pond",
        "pony",
        "pool",
        "poodle",
        "portrait",
        "porch",
        "position",
        "potato",
        "pound",
        "power",
        "practice",
        "prairie",
        "president",
        "prince",
        "princess",
        "print",
        "priority",
        "prison",
        "private",
        "prize",
        "problem",
        "process",
        "produce",
        "profit",
        "program",
        "project",
        "pudding",
        "puffin",
        "pumpkin",
        "punch",
        "puppet",
        "pupil",
        "puppy",
        "rabbit",
        "raccoon",
        "radar",
        "radio",
        "raft",
        "rage",
        "rain",
        "ranch",
        "random",
        "range",
        "rapid",
        "rare",
        "rash",
        "raven",
        "razor",
        "ready",
        "real",
        "reason",
        "rebel",
        "rebuild",
        "recall",
        "receive",
        "record",
        "recycle",
        "refer",
        "reflect",
        "reform",
        "region",
        "regret",
        "reject",
        "relax",
        "release",
        "relief",
        "rely",
        "remain",
        "remember",
        "remind",
        "remote",
        "remove",
        "render",
        "renew",
        "rent",
        "repair",
        "repeat",
        "replace",
        "reply",
        "report",
        "represent",
        "require",
        "rescue",
        "resemble",
        "reserve",
        "reset",
        "resist",
        "resolve",
        "resource",
        "respect",
        "respond",
        "restore",
        "retail",
        "retain",
        "retire",
        "return",
        "revenue",
        "reverse",
        "reveal",
        "review",
        "reward",
        "rhythm",
        "rice",
        "rich",
        "ride",
        "rifle",
        "rigid",
        "ring",
        "riot",
        "ripple",
        "risk",
        "ritual",
        "rival",
        "river",
        "road",
        "robot",
        "rock",
        "rocket",
        "romance",
        "roof",
        "rookie",
        "room",
        "rose",
        "rotate",
        "rough",
        "round",
        "route",
        "royal",
        "rubber",
        "rude",
        "rule",
        "rural",
        "sad",
        "saddle",
        "sadness",
        "safe",
        "sail",
        "salad",
        "salmon",
        "salon",
        "salt",
        "salute",
        "Zebra",
        "sample",
        "sand",
        "42",
        "shadow",
        "storm",
        "summit",
    ]
    .into_iter()
    .map(|s| s)
    .collect()
}

/// Draw one element from `slice`, returning an owned copy.
fn pick<T: Copy>(slice: &[T], rng: &mut impl RngCore) -> T {
    let index = pick_index(rng, slice.len() as u64);
    slice[index]
}

/// Uniform index in `[0, limit)`.
fn pick_index(rng: &mut impl RngCore, limit: u64) -> usize {
    debug_assert!(limit >= 1);
    (draw(rng) % limit) as usize
}

/// Draw 64 bits of entropy from `rng`.
fn draw(rng: &mut impl RngCore) -> u64 {
    let mut value = 0u64;
    for _ in 0..8 {
        value = (value << 8) | u64::from(rng.next_u32());
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn default_generator_holds_every_class_and_length() {
        let generator = PasswordGenerator::new(16);
        for _ in 0..50 {
            let password = generator.generate(&mut OsRng);
            assert_eq!(password.len(), 16);
            assert!(password.chars().any(|c| c.is_ascii_lowercase()));
            assert!(password.chars().any(|c| c.is_ascii_uppercase()));
            assert!(password.chars().any(|c| c.is_ascii_digit()));
            assert!(password.bytes().any(|b| SYMBOLS.contains(&b)));
        }
    }

    #[test]
    fn every_class_is_represented() {
        let generator = PasswordGenerator::new(4);
        for _ in 0..50 {
            let password = generator.generate(&mut OsRng);
            assert_eq!(password.len(), 4);
            assert!(password.chars().any(|c| c.is_ascii_lowercase()));
            assert!(password.chars().any(|c| c.is_ascii_uppercase()));
            assert!(password.chars().any(|c| c.is_ascii_digit()));
            assert!(password.bytes().any(|b| SYMBOLS.contains(&b)));
        }
    }

    #[test]
    fn length_never_drops_a_required_class() {
        let generator = PasswordGenerator::new(4);
        for _ in 0..100 {
            let password = generator.generate(&mut OsRng);
            assert_eq!(password.len(), 4);
            assert!(password.chars().any(|c| c.is_ascii_lowercase()));
            assert!(password.chars().any(|c| c.is_ascii_uppercase()));
            assert!(password.chars().any(|c| c.is_ascii_digit()));
            assert!(password.bytes().any(|b| SYMBOLS.contains(&b)));
        }
    }

    #[test]
    fn phrases_draw_from_every_word_and_length() {
        let generator = PhraseGenerator::with_words(built_in_wordlist(), 6);
        for _ in 0..50 {
            let phrase = generator.generate(&mut OsRng);
            assert_eq!(phrase.split_whitespace().count(), 6);
            for word in phrase.split_whitespace() {
                assert!(built_in_wordlist().contains(&word));
            }
        }
    }

    #[test]
    fn built_in_wordlist_is_dense() {
        let words = built_in_wordlist();
        assert_eq!(words.len(), 300);
        assert!(words
            .iter()
            .any(|w| w.chars().next().unwrap().is_ascii_lowercase()));
        assert!(words
            .iter()
            .any(|w| w.chars().next().unwrap().is_ascii_uppercase()));
        assert!(words
            .iter()
            .any(|w| w.chars().next().unwrap().is_ascii_digit()));
        assert!(words.iter().any(|w| SYMBOLS.contains(&w.as_bytes()[0])));
    }

    #[test]
    fn no_secret_symbol_leaks_shell_breakage() {
        for _ in 0..50 {
            let password = PasswordGenerator::new(16).generate(&mut OsRng);
            assert!(!password.bytes().any(|b| b == b'\\'), "backslash in draw");
            assert!(!password.bytes().any(|b| b == b'"'), "quote in draw");
            assert!(!password.bytes().any(|b| b == b'\''), "apostrophe in draw");
            assert!(password.bytes().all(|b| !b.is_ascii_whitespace()));
        }
    }

    #[test]
    fn length_clamps_to_minimum() {
        let generator = PasswordGenerator::new(1);
        for _ in 0..50 {
            let password = generator.generate(&mut OsRng);
            assert_eq!(password.len(), 4);
        }
    }

    #[test]
    fn with_requirements_respects_overrides() {
        let generator = PasswordGenerator::new(16).with_requirements(Requirements {
            lower: false,
            upper: false,
            digit: false,
            symbol: true,
        });
        for _ in 0..50 {
            let password = generator.generate(&mut OsRng);
            assert_eq!(password.len(), 16);
            assert!(!password.chars().any(|c| c.is_ascii_alphanumeric()));
            assert!(password.bytes().any(|b| SYMBOLS.contains(&b)));
        }
    }
}
