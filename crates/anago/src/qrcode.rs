//! Encoding a config as a QR code, and asking how wide the terminal is
//! (DESIGN.md §10.2, §8).
//!
//! The two impure halves of the phone path. Encoding is `qrcodegen`'s —
//! §4 principle 1, and the reason it is not ours: Reed-Solomon, masking
//! and version selection are solved, and solving them again fails in
//! the one shape a unit test cannot see. Measuring a terminal is an
//! ioctl.
//!
//! Everything between them — quiet zone, block style, whether it fits —
//! is [`anago_core::qr`], where it is tested.

use anago_core::qr::Modules;
use anago_core::wgconf::SecretText;
use qrcodegen::{QrCode, QrCodeEcc};

/// Turns a rendered config into a module grid.
///
/// **Error correction Low.** A config is 250-odd bytes and every level
/// above Low costs modules, which costs columns — and the difference
/// between fitting an 80-column terminal and not is the difference
/// between a code that scans and one that wraps. The redundancy is
/// there for print smudged on a box; a screen a phone is held up to for
/// five seconds is not that.
///
/// `None` when the text is too long for any version, which a wg config
/// is nowhere near — the check is here because "too long" silently
/// truncated would be a code that scans and hands over half a key.
pub fn encode(text: &SecretText) -> Option<Modules> {
    // `encode_binary`, not `encode_text`: a config may hold any UTF-8,
    // and the byte segment is what a scanner hands back unchanged.
    let code = QrCode::encode_binary(text.expose().as_bytes(), QrCodeEcc::Low).ok()?;
    let size = usize::try_from(code.size()).ok()?;
    let mut dark = Vec::with_capacity(size * size);
    for y in 0..code.size() {
        for x in 0..code.size() {
            dark.push(code.get_module(x, y));
        }
    }
    Modules::new(size, dark)
}

/// How wide the terminal is, in columns.
///
/// The default when there is nothing to ask — output is a pipe, or the
/// ioctl is not available. Eighty is the width a terminal has when
/// nobody has said otherwise, and guessing wider would draw a code that
/// wraps.
pub const ASSUMED_COLUMNS: usize = 80;

/// Asks the terminal on standard output how wide it is.
///
/// **Human verification needed**: an ioctl on a real terminal.
pub fn columns() -> usize {
    use std::os::unix::io::AsRawFd;

    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: `size` outlives the call and is the struct TIOCGWINSZ
    // fills in; the descriptor is this process's own standard output.
    let asked = unsafe {
        libc::ioctl(
            std::io::stdout().as_raw_fd(),
            libc::TIOCGWINSZ,
            &mut size as *mut libc::winsize,
        )
    };
    if asked != 0 || size.ws_col == 0 {
        return ASSUMED_COLUMNS;
    }
    usize::from(size.ws_col)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anago_core::qr::{self, Blocks, Drawing};

    fn config() -> SecretText {
        use anago_core::state::PrivateKey;
        use anago_core::subnet::Subnet;
        use anago_core::wgconf::{export_profile, ClientProfile};

        export_profile(&ClientProfile {
            address: "10.100.0.3".parse().unwrap(),
            subnet: Subnet::parse("10.100.0.0/24").unwrap(),
            private_key: PrivateKey::new("cGhvbmUgcHJpdmF0ZSBrZXkgaGVyZSAxMjM0NTY3OD0="),
            server_public_key: "Xtt7u1I5qnMB8k6yMkjTDpJAc+3tPLPV9dg/yeb+qdE=".to_string(),
            server_endpoint: "net.example.com:51820".to_string(),
        })
    }

    #[test]
    fn a_real_config_encodes_to_something_a_terminal_can_hold() {
        let modules = encode(&config()).expect("a wg config is nowhere near too long");
        // Version 1 is 21 modules and grows by 4 a version; whatever
        // version this lands on, it has to be one of those.
        assert!(modules.size() >= 21, "{}", modules.size());
        assert_eq!((modules.size() - 21) % 4, 0, "{}", modules.size());

        // The size that matters: the compact style has to fit the
        // terminal width nobody has changed.
        assert!(
            qr::columns(modules.size(), Blocks::Half) <= ASSUMED_COLUMNS,
            "{} modules is {} columns",
            modules.size(),
            qr::columns(modules.size(), Blocks::Half)
        );
        assert!(matches!(
            qr::draw(&modules, ASSUMED_COLUMNS),
            Drawing::Code(_)
        ));
    }

    #[test]
    fn the_finder_patterns_are_where_a_scanner_looks_for_them() {
        // Not a test of qrcodegen — a test that the grid is read out
        // the right way round. A transposed or flipped copy still draws
        // a plausible code, and the only symptom is a phone that will
        // not read it.
        let modules = encode(&config()).unwrap();
        // A finder is a 7×7 ring: dark border, light gap inside it,
        // 3×3 dark centre.
        let finder = |x: usize, y: usize| {
            (0..7).all(|i| {
                modules.is_dark(x + i, y)
                    && modules.is_dark(x + i, y + 6)
                    && modules.is_dark(x, y + i)
                    && modules.is_dark(x + 6, y + i)
            }) && (1..6).all(|i| !modules.is_dark(x + i, y + 1) && !modules.is_dark(x + 1, y + i))
                && (2..5).all(|i| modules.is_dark(x + i, y + 3))
        };

        let last = modules.size() - 7;
        assert!(finder(0, 0), "top left");
        assert!(finder(last, 0), "top right");
        assert!(finder(0, last), "bottom left");
        // Three corners and not the fourth: that asymmetry is how a
        // scanner works out which way up the code is, and it is the
        // thing a transposed read-out would keep while a flipped one
        // would move.
        assert!(!finder(last, last), "bottom right has none");
    }

    #[test]
    fn a_terminal_that_cannot_be_asked_is_assumed_narrow() {
        // Under `cargo test` standard output is a pipe, so this is the
        // fallback path. Guessing wider than eighty would draw a code
        // that wraps on the terminals that still are eighty.
        assert_eq!(ASSUMED_COLUMNS, 80);
        assert!(columns() >= 1, "never zero, whatever the ioctl said");
    }
}
