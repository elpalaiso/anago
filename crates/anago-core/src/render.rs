//! What `anago ls` prints (DESIGN.md §8).
//!
//! Pure text: rows in, a table out. The two callers know different
//! things and both go through here — on the server, `ls` reads the
//! state file and asks `wg show` when each device was last heard from;
//! on a device, the API answers with identity only, so the handshake
//! column is [`LastHandshake::Unknown`] rather than a guess.
//!
//! Column widths count East Asian characters as two columns, because a
//! Korean device name is a first-class name here (§8.1) and a table
//! that only lines up for ASCII is a table that does not line up.

use std::fmt;
use std::net::Ipv4Addr;

/// Characters of a public key kept before the ellipsis. Enough to tell
/// two keys apart at a glance, short enough to leave the table
/// readable on an 80-column terminal.
pub const KEY_PREFIX_LEN: usize = 8;

/// When a device last completed a handshake with the hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastHandshake {
    /// Nobody asked wg — `ls` run on a device, which only has the API
    /// (§8: M0's `GET /peers` carries identity, not liveness).
    Unknown,
    /// wg was asked and has never seen this peer.
    Never,
    /// Unix epoch seconds of the last handshake.
    At(i64),
}

/// One line of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRow {
    pub name: String,
    pub address: Ipv4Addr,
    pub public_key: String,
    pub last_handshake: LastHandshake,
}

/// Renders the device table, or a line saying there are none.
///
/// `now` is Unix epoch seconds; handshakes are shown relative to it,
/// which is what a person actually wants to know ("2m ago" beats a
/// timestamp they have to subtract).
pub fn peer_table(rows: &[PeerRow], now: i64) -> String {
    if rows.is_empty() {
        return "no devices yet — run `anago code` on the server to add one\n".to_string();
    }

    let headers = ["NAME", "ADDRESS", "PUBLIC KEY", "LAST HANDSHAKE"];
    let cells: Vec<[String; 4]> = rows
        .iter()
        .map(|row| {
            [
                row.name.clone(),
                row.address.to_string(),
                abbreviate_key(&row.public_key),
                format_handshake(row.last_handshake, now),
            ]
        })
        .collect();

    let mut widths = headers.map(display_width);
    for row in &cells {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(display_width(cell));
        }
    }

    let mut out = String::new();
    write_row(&headers.map(String::from), &widths, &mut out);
    for row in &cells {
        write_row(row, &widths, &mut out);
    }
    out
}

/// Two spaces between columns, no trailing blanks — a padded last
/// column would show up as invisible whitespace in anything that pipes
/// this.
fn write_row(cells: &[String; 4], widths: &[usize; 4], out: &mut String) {
    let mut line = String::new();
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            line.push_str("  ");
        }
        line.push_str(cell);
        if i + 1 < cells.len() {
            for _ in display_width(cell)..widths[i] {
                line.push(' ');
            }
        }
    }
    out.push_str(line.trim_end());
    out.push('\n');
}

/// First [`KEY_PREFIX_LEN`] characters and an ellipsis. Keys shorter
/// than that are printed whole rather than padded into a lie.
pub fn abbreviate_key(key: &str) -> String {
    if key.chars().count() <= KEY_PREFIX_LEN {
        return key.to_string();
    }
    let prefix: String = key.chars().take(KEY_PREFIX_LEN).collect();
    format!("{prefix}…")
}

/// `2m ago`, `never`, or `—` when nothing asked.
pub fn format_handshake(handshake: LastHandshake, now: i64) -> String {
    match handshake {
        LastHandshake::Unknown => "—".to_string(),
        LastHandshake::Never => "never".to_string(),
        LastHandshake::At(at) => format_ago(now.saturating_sub(at)),
    }
}

/// Coarse relative time. Nobody reading `ls` needs the seconds in "3
/// days ago", and a clock that ran backwards should not print a
/// negative age.
fn format_ago(seconds: i64) -> String {
    match seconds {
        i64::MIN..=9 => "just now".to_string(),
        10..=59 => format!("{seconds}s ago"),
        60..=3599 => format!("{}m ago", seconds / 60),
        3600..=86_399 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86_400),
    }
}

/// Terminal columns a string occupies, counting East Asian wide
/// characters as two.
///
/// An approximation of UAX #11: the ranges below cover Hangul, Han,
/// Kana, and full-width forms, which is what device names in this
/// project actually contain. Getting the long tail exactly right needs
/// a Unicode table, and core takes no dependencies (§4).
fn display_width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

fn char_width(c: char) -> usize {
    match c as u32 {
        0x1100..=0x115F // Hangul Jamo
        | 0x2E80..=0x303E // CJK radicals, Kangxi, CJK symbols
        | 0x3041..=0x33FF // Kana, Hangul Compatibility Jamo, CJK compatibility
        | 0x3400..=0x4DBF // CJK Extension A
        | 0x4E00..=0x9FFF // CJK Unified Ideographs
        | 0xA960..=0xA97F // Hangul Jamo Extended-A
        | 0xAC00..=0xD7A3 // Hangul Syllables
        | 0xF900..=0xFAFF // CJK Compatibility Ideographs
        | 0xFE30..=0xFE6F // CJK compatibility forms
        | 0xFF00..=0xFF60 // Full-width forms
        | 0xFFE0..=0xFFE6
        | 0x20000..=0x3FFFD => 2,
        _ => 1,
    }
}

impl fmt::Display for LastHandshake {
    /// Absolute form, for logs and messages that have no `now` to be
    /// relative to.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LastHandshake::Unknown => f.write_str("unknown"),
            LastHandshake::Never => f.write_str("never"),
            LastHandshake::At(at) => write!(f, "{at}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_755_500_000;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    fn row(name: &str, address: &str, key: &str, handshake: LastHandshake) -> PeerRow {
        PeerRow {
            name: name.to_string(),
            address: ip(address),
            public_key: key.to_string(),
            last_handshake: handshake,
        }
    }

    #[test]
    fn an_empty_network_says_what_to_do_next() {
        // A bare header row would read like a bug on a fresh server.
        assert_eq!(
            peer_table(&[], NOW),
            "no devices yet — run `anago code` on the server to add one\n"
        );
    }

    #[test]
    fn renders_the_table_the_server_can_fill_in() {
        let rows = [
            row(
                "macbook",
                "10.100.0.2",
                "bWFjYm9va3B1YmxpY2tleQ==",
                LastHandshake::At(NOW - 120),
            ),
            row(
                "desktop",
                "10.100.0.3",
                "ZGVza3RvcHB1YmxpY2tleQ==",
                LastHandshake::Never,
            ),
        ];
        let expected = "\
NAME     ADDRESS     PUBLIC KEY  LAST HANDSHAKE
macbook  10.100.0.2  bWFjYm9v…   2m ago
desktop  10.100.0.3  ZGVza3Rv…   never
";
        assert_eq!(peer_table(&rows, NOW), expected);
    }

    #[test]
    fn a_device_that_cannot_ask_wg_shows_a_dash() {
        // `ls` over the API: M0's /peers carries identity only, so the
        // column says "not known" rather than "never".
        let rows = [row(
            "macbook",
            "10.100.0.2",
            "bWFjYm9va3B1YmxpY2tleQ==",
            LastHandshake::Unknown,
        )];
        let table = peer_table(&rows, NOW);
        assert!(table.ends_with("—\n"), "{table}");
        assert!(!table.contains("never"), "{table}");
    }

    #[test]
    fn columns_line_up_with_korean_names() {
        // 맥북 is four terminal columns, not two: padding by character
        // count would leave the table ragged.
        let rows = [
            row("맥북", "10.100.0.2", "a", LastHandshake::Never),
            row("macbook2", "10.100.0.3", "b", LastHandshake::Never),
        ];
        let table = peer_table(&rows, NOW);
        let starts: Vec<usize> = table
            .lines()
            .map(|line| display_width(line.split("10.100").next().unwrap()))
            .collect();
        // Header has no address, so compare the two data rows.
        assert_eq!(starts[1], starts[2], "{table}");
        assert!(table.contains("맥북      10.100.0.2"), "{table}");
    }

    #[test]
    fn column_widths_follow_the_longest_value() {
        let rows = [row(
            "a-very-long-device-name-here",
            "10.100.0.2",
            "k",
            LastHandshake::Never,
        )];
        let table = peer_table(&rows, NOW);
        let header = table.lines().next().unwrap();
        let data = table.lines().nth(1).unwrap();
        // Both rows put ADDRESS at the same column.
        assert_eq!(
            header.find("ADDRESS").unwrap(),
            data.find("10.100.0.2").unwrap(),
            "{table}"
        );
    }

    #[test]
    fn no_line_carries_trailing_whitespace() {
        let rows = [
            row("macbook", "10.100.0.2", "k", LastHandshake::Never),
            row("desktop", "10.100.0.3", "k", LastHandshake::At(NOW)),
        ];
        for line in peer_table(&rows, NOW).lines() {
            assert_eq!(line, line.trim_end(), "trailing space in {line:?}");
        }
    }

    #[test]
    fn keys_are_abbreviated_but_short_ones_are_left_alone() {
        assert_eq!(abbreviate_key("bWFjYm9va3B1YmxpY2tleQ=="), "bWFjYm9v…");
        assert_eq!(abbreviate_key("12345678"), "12345678");
        assert_eq!(abbreviate_key("123456789"), "12345678…");
        assert_eq!(abbreviate_key(""), "");
        // wg keys are base64, but the cut counts characters, so a
        // multi-byte string is never sliced mid-character.
        assert_eq!(abbreviate_key("맥북맥북맥북맥북맥북"), "맥북맥북맥북맥북…");
    }

    #[test]
    fn relative_times_read_the_way_a_person_asks() {
        let cases = [
            (0, "just now"),
            (9, "just now"),
            (10, "10s ago"),
            (59, "59s ago"),
            (60, "1m ago"),
            (119, "1m ago"),
            (3_599, "59m ago"),
            (3_600, "1h ago"),
            (86_399, "23h ago"),
            (86_400, "1d ago"),
            (172_800, "2d ago"),
        ];
        for (age, expected) in cases {
            assert_eq!(
                format_handshake(LastHandshake::At(NOW - age), NOW),
                expected,
                "age {age}"
            );
        }
    }

    #[test]
    fn a_clock_that_ran_backwards_does_not_print_a_negative_age() {
        assert_eq!(
            format_handshake(LastHandshake::At(NOW + 60), NOW),
            "just now"
        );
        assert_eq!(
            format_handshake(LastHandshake::At(i64::MAX), NOW),
            "just now"
        );
        // And an absurdly old timestamp saturates instead of wrapping.
        assert!(format_handshake(LastHandshake::At(i64::MIN), NOW).ends_with("d ago"));
    }

    #[test]
    fn handshake_has_an_absolute_form_for_logs() {
        assert_eq!(LastHandshake::Unknown.to_string(), "unknown");
        assert_eq!(LastHandshake::Never.to_string(), "never");
        assert_eq!(LastHandshake::At(NOW).to_string(), "1755500000");
    }
}
