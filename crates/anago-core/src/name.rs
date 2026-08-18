//! Device names (DESIGN.md §8.1).
//!
//! A name is the key `anago rm` takes, a path segment in
//! `DELETE /api/v1/peers/{name}`, and — from M3 — a hostname. It is
//! also the thing a person reads in `anago ls`, which is why Korean
//! names are first class here rather than an ASCII slug.
//!
//! Canonical form is trimmed and lower-cased. The server stores that
//! form and hands it back from `join`, so `MacBook` and `macbook` are
//! one device, not two.
//!
//! **Known limit (M0)**: no Unicode normalization. std has none and
//! core takes no dependencies (§4 principle 4), so a decomposed `맥북`
//! and a composed `맥북` register as two names that look identical.
//! §8.1 records this; fixing it means a dependency in the binary.

use std::fmt;

/// Longest accepted name, in characters (not bytes).
pub const MAX_LEN: usize = 32;

/// Names anago keeps for itself. `server` is the hub, which M3 will
/// want to resolve by that name.
pub const RESERVED: [&str; 1] = ["server"];

/// A device name in canonical form.
///
/// Built only by [`DeviceName::parse`], so holding one means the rules
/// of §8.1 already passed — callers compare and store it as is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceName(String);

impl DeviceName {
    /// Trims, lower-cases, and checks §8.1. What it will not do is
    /// rewrite a name into something legal — a device called `my mac`
    /// is reported, not silently turned into `my-mac`, because the
    /// person has to recognize the name they will type later.
    pub fn parse(input: &str) -> Result<DeviceName, NameError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(NameError::Empty);
        }
        let name: String = trimmed.to_lowercase();

        let len = name.chars().count();
        if len > MAX_LEN {
            return Err(NameError::TooLong(len));
        }
        for c in name.chars() {
            if !is_allowed(c) {
                return Err(NameError::BadChar(c));
            }
        }
        // Leading/trailing `-` or `_`: legal inside a name, but an edge
        // hyphen is not a legal DNS label and reads like a typo.
        let first = name.chars().next().expect("non-empty");
        let last = name.chars().next_back().expect("non-empty");
        if !first.is_alphanumeric() {
            return Err(NameError::BadEdge(first));
        }
        if !last.is_alphanumeric() {
            return Err(NameError::BadEdge(last));
        }
        if RESERVED.contains(&name.as_str()) {
            return Err(NameError::Reserved);
        }
        Ok(DeviceName(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Letters and digits in any script, plus `-` and `_`. Everything else
/// is out: `.` collides with M3's label boundary, `/ % ? # :` break the
/// URL path, and whitespace or control characters break wg configs and
/// shell quoting (§8.1).
fn is_allowed(c: char) -> bool {
    c.is_alphanumeric() || c == '-' || c == '_'
}

/// Why a name was refused, one variant per sentence the user can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// Nothing but whitespace.
    Empty,
    /// Too many characters; carries the count that was offered.
    TooLong(usize),
    /// A character outside the allowed set.
    BadChar(char),
    /// Starts or ends with `-`/`_`.
    BadEdge(char),
    /// One of [`RESERVED`].
    Reserved,
    /// Already registered by another device. Not produced by
    /// [`DeviceName::parse`] — the state file answers this one, via
    /// [`is_taken`].
    Taken,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameError::Empty => write!(f, "device name is empty"),
            NameError::TooLong(len) => {
                write!(f, "device name is {len} characters, the limit is {MAX_LEN}")
            }
            NameError::BadChar(c) => {
                write!(
                    f,
                    "device names cannot contain {c:?}; use letters, digits, '-' or '_'"
                )
            }
            NameError::BadEdge(c) => {
                write!(f, "device names cannot start or end with {c:?}")
            }
            NameError::Reserved => write!(f, "that device name is reserved"),
            NameError::Taken => write!(f, "a device with that name is already registered"),
        }
    }
}

impl std::error::Error for NameError {}

/// Whether `candidate` collides with a name already in the state file.
///
/// Compares canonical forms, which is why `MacBook` cannot join a
/// network that already has `macbook`. `existing` is what the state
/// file holds; entries that are not canonical (hand-edited) still match
/// when they are spelled the same.
pub fn is_taken<'a>(existing: impl IntoIterator<Item = &'a str>, candidate: &DeviceName) -> bool {
    existing.into_iter().any(|name| name == candidate.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(input: &str) -> DeviceName {
        DeviceName::parse(input).expect("valid name")
    }

    #[test]
    fn canonicalizes_case_and_surrounding_space() {
        assert_eq!(name("MacBook").as_str(), "macbook");
        assert_eq!(name("  desktop\n").as_str(), "desktop");
        assert_eq!(name("MACBOOK").to_string(), "macbook");
        // Idempotent: parsing a canonical name changes nothing.
        let once = name("MacBook");
        assert_eq!(DeviceName::parse(once.as_str()).unwrap(), once);
    }

    #[test]
    fn korean_names_are_first_class() {
        // DESIGN.md's own example is `--name 맥북`.
        assert_eq!(name("맥북").as_str(), "맥북");
        assert_eq!(name("데스크톱").as_str(), "데스크톱");
        assert_eq!(name(" 맥북 ").as_str(), "맥북");
        assert_eq!(name("맥북-2").as_str(), "맥북-2");
    }

    #[test]
    fn allows_digits_hyphens_and_underscores_inside() {
        for input in ["mac-book", "mac_book", "macbook2", "2nd-mac", "a", "9"] {
            assert_eq!(name(input).as_str(), input);
        }
    }

    #[test]
    fn rejects_empty_and_whitespace_only() {
        assert_eq!(DeviceName::parse(""), Err(NameError::Empty));
        assert_eq!(DeviceName::parse("   "), Err(NameError::Empty));
        assert_eq!(DeviceName::parse("\t\n"), Err(NameError::Empty));
    }

    #[test]
    fn rejects_characters_that_would_break_a_url_or_a_config() {
        // A dot would collide with M3's label boundary.
        assert_eq!(DeviceName::parse("mac.book"), Err(NameError::BadChar('.')));
        assert_eq!(DeviceName::parse("mac/book"), Err(NameError::BadChar('/')));
        assert_eq!(
            DeviceName::parse("mac%20book"),
            Err(NameError::BadChar('%'))
        );
        assert_eq!(DeviceName::parse("mac?book"), Err(NameError::BadChar('?')));
        assert_eq!(DeviceName::parse("mac#book"), Err(NameError::BadChar('#')));
        assert_eq!(DeviceName::parse("mac:book"), Err(NameError::BadChar(':')));
        // Inner whitespace is not trimmed away — it is rejected.
        assert_eq!(DeviceName::parse("my mac"), Err(NameError::BadChar(' ')));
        assert_eq!(DeviceName::parse("my\tmac"), Err(NameError::BadChar('\t')));
        assert_eq!(
            DeviceName::parse("mac\u{0}book"),
            Err(NameError::BadChar('\u{0}'))
        );
        assert_eq!(DeviceName::parse("mac\"book"), Err(NameError::BadChar('"')));
    }

    #[test]
    fn rejects_hyphen_or_underscore_at_the_edges() {
        assert_eq!(DeviceName::parse("-mac"), Err(NameError::BadEdge('-')));
        assert_eq!(DeviceName::parse("mac-"), Err(NameError::BadEdge('-')));
        assert_eq!(DeviceName::parse("_mac"), Err(NameError::BadEdge('_')));
        assert_eq!(DeviceName::parse("mac_"), Err(NameError::BadEdge('_')));
        assert_eq!(DeviceName::parse("-"), Err(NameError::BadEdge('-')));
        // Trimming happens first, so a padded edge hyphen still fails.
        assert_eq!(DeviceName::parse("  -mac  "), Err(NameError::BadEdge('-')));
    }

    #[test]
    fn length_is_counted_in_characters_not_bytes() {
        let ascii = "a".repeat(MAX_LEN);
        assert_eq!(name(&ascii).as_str().chars().count(), MAX_LEN);
        assert_eq!(
            DeviceName::parse(&"a".repeat(MAX_LEN + 1)),
            Err(NameError::TooLong(33))
        );

        // 32 Korean characters are 96 bytes but still 32 characters.
        let korean = "맥".repeat(MAX_LEN);
        assert_eq!(korean.len(), 96);
        assert_eq!(name(&korean).as_str().chars().count(), MAX_LEN);
        assert_eq!(
            DeviceName::parse(&"맥".repeat(MAX_LEN + 1)),
            Err(NameError::TooLong(33))
        );
    }

    #[test]
    fn reserves_the_hub_name() {
        assert_eq!(DeviceName::parse("server"), Err(NameError::Reserved));
        // Case-folding happens before the check.
        assert_eq!(DeviceName::parse("SERVER"), Err(NameError::Reserved));
        assert_eq!(DeviceName::parse(" Server "), Err(NameError::Reserved));
        // Near misses are fine.
        assert_eq!(name("servers").as_str(), "servers");
        assert_eq!(name("my-server").as_str(), "my-server");
    }

    #[test]
    fn errors_say_what_to_fix() {
        assert_eq!(NameError::Empty.to_string(), "device name is empty");
        assert_eq!(
            NameError::TooLong(40).to_string(),
            "device name is 40 characters, the limit is 32"
        );
        assert_eq!(
            NameError::BadChar('.').to_string(),
            "device names cannot contain '.'; use letters, digits, '-' or '_'"
        );
        assert_eq!(
            NameError::BadEdge('-').to_string(),
            "device names cannot start or end with '-'"
        );
        assert_eq!(
            NameError::Reserved.to_string(),
            "that device name is reserved"
        );
        assert_eq!(
            NameError::Taken.to_string(),
            "a device with that name is already registered"
        );
    }

    #[test]
    fn duplicate_detection_compares_canonical_forms() {
        let registered = ["macbook", "데스크톱"];
        assert!(is_taken(registered, &name("macbook")));
        // The whole point of canonicalizing: these are the same device.
        assert!(is_taken(registered, &name("MacBook")));
        assert!(is_taken(registered, &name("  MACBOOK ")));
        assert!(is_taken(registered, &name("데스크톱")));

        assert!(!is_taken(registered, &name("phone")));
        assert!(!is_taken(registered, &name("macbook2")));
        assert!(!is_taken([], &name("macbook")));
    }

    #[test]
    fn duplicate_detection_reads_state_file_strings() {
        // What the server actually has: names owned by the state file.
        let stored: Vec<String> = vec!["macbook".to_string(), "맥북".to_string()];
        assert!(is_taken(stored.iter().map(String::as_str), &name("맥북")));
        assert!(!is_taken(stored.iter().map(String::as_str), &name("phone")));
    }
}
