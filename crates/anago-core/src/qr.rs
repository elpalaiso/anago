//! Drawing a QR code on a terminal (DESIGN.md §10.2, §8).
//!
//! The encoding — Reed-Solomon, masking, version selection — is
//! `qrcodegen`'s job in the binary crate, for the reason §4 principle 1
//! gives: it is a solved problem, and solving it again goes wrong in
//! exactly one shape, "the phone will not scan it", which no unit test
//! catches.
//!
//! What is left is turning a grid of light and dark squares into
//! characters, and that is a pure function with a lot of ways to be
//! quietly wrong. It lives here so `cargo test` catches a regression in
//! it, and so this crate stays free of the encoder (§4 principle 4).
//!
//! Three things decide whether a phone reads what appears:
//!
//! - **The quiet zone.** Four light modules on every side, or a scanner
//!   has nothing to find the code's edges against.
//! - **The proportions.** A terminal cell is about twice as tall as it
//!   is wide, so one character per module draws a code twice as tall as
//!   it is wide. Both styles here correct for that, in opposite
//!   directions.
//! - **Which way round it is.** A QR is dark modules on a light ground.
//!   The character alone does not say that: on a dark-theme terminal
//!   `█` is the light one. So the colours are stated rather than
//!   inherited.

use std::fmt;

/// A version-1 code: the smallest a QR ever is.
///
/// Nothing anago encodes comes out this small, but the columns it needs
/// are a floor — a window too narrow for *this* is one no answer from
/// the hub could ever be drawn in, which is worth knowing before a
/// single-use join code is spent.
pub const SMALLEST: usize = 21;

/// Light modules on every side, in modules. Four is what the spec asks
/// for, and a scanner that cannot find the edges reports nothing rather
/// than reporting a problem.
pub const QUIET: usize = 4;

/// A QR code as its grid of modules.
///
/// Row-major, `true` for dark. The binary fills this in from
/// `qrcodegen`; nothing here knows how those bits were chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modules {
    size: usize,
    dark: Vec<bool>,
}

impl Modules {
    /// `None` when the grid is not `size` × `size` — a length and a
    /// side that disagree would draw a plausible-looking code out of
    /// misaligned rows.
    pub fn new(size: usize, dark: Vec<bool>) -> Option<Modules> {
        (size > 0 && dark.len() == size * size).then_some(Modules { size, dark })
    }

    pub fn size(&self) -> usize {
        self.size
    }

    /// Dark modules inside the code; light everywhere outside it, which
    /// is what makes the quiet zone fall out of the same lookup.
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        if x >= self.size || y >= self.size {
            return false;
        }
        self.dark[y * self.size + x]
    }
}

/// How much of a character each module gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocks {
    /// Two characters wide, one tall — `██` for a dark module.
    ///
    /// A cell is about twice as tall as it is wide, so this comes out
    /// square. It also needs nothing but `█` and a space, which every
    /// font that can draw a terminal has. Preferred wherever it fits.
    Full,
    /// One character wide, half of one tall.
    ///
    /// Two module rows share a character: `▀` is dark above and light
    /// below, `▄` the other way, `█` both. Square again, in half the
    /// columns — which is the difference between a code that fits an
    /// 80-column terminal and one that does not.
    Half,
}

/// The columns a code of this size needs, quiet zone included.
pub fn columns(size: usize, blocks: Blocks) -> usize {
    let modules = size + 2 * QUIET;
    match blocks {
        Blocks::Full => modules * 2,
        Blocks::Half => modules,
    }
}

/// The lines it takes up.
pub fn rows(size: usize, blocks: Blocks) -> usize {
    let modules = size + 2 * QUIET;
    match blocks {
        Blocks::Full => modules,
        // Two module rows per line, and an odd count still needs the
        // line that holds the last one.
        Blocks::Half => modules.div_ceil(2),
    }
}

/// The widest style that fits, or `None` when neither does.
///
/// `Full` first: it draws bigger, and it draws with characters every
/// terminal font has. `Half` is the fallback rather than the default
/// because half blocks are the part a sparse font gets wrong, and a
/// missing glyph in a QR code is a code that does not scan.
pub fn fit(size: usize, available: usize) -> Option<Blocks> {
    [Blocks::Full, Blocks::Half]
        .into_iter()
        .find(|&blocks| columns(size, blocks) <= available)
}

/// Black on white, stated rather than inherited.
///
/// A QR is dark modules on a light ground. Which character means
/// "dark" depends on the terminal's theme, and on a dark one `█` is the
/// light square — so the code would be drawn inverted. Some scanners
/// read an inverted code and some do not, and "the phone will not scan
/// it" is the failure this whole path is arranged to avoid.
const INK: &str = "\u{1b}[30;47m";

/// Ends every line, so a code that is half-copied out of a terminal
/// does not leave the rest of the session on a white background.
const RESET: &str = "\u{1b}[0m";

/// Draws the code, or says it cannot be drawn this narrow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drawing {
    /// Ready to print. Ends in a newline.
    Code(String),
    /// The terminal is too narrow for even the compact style.
    ///
    /// **Not a smaller code.** A QR wider than the terminal wraps, and
    /// a wrapped QR still looks like a QR — it just cannot be read, and
    /// the person finds that out by holding a phone up to it. Saying so
    /// is the only honest answer.
    TooNarrow { needed: usize, available: usize },
}

/// Draws `modules` for a terminal `available` columns wide.
pub fn draw(modules: &Modules, available: usize) -> Drawing {
    let Some(blocks) = fit(modules.size(), available) else {
        return Drawing::TooNarrow {
            needed: columns(modules.size(), Blocks::Half),
            available,
        };
    };
    Drawing::Code(draw_with(modules, blocks))
}

/// Draws it in a style the caller has already chosen.
pub fn draw_with(modules: &Modules, blocks: Blocks) -> String {
    let span = modules.size() + 2 * QUIET;
    // Every lookup is offset by the quiet zone, and `is_dark` answers
    // "light" for anything outside the code — so the margin is drawn by
    // the same loop as the code, with nothing to keep in step.
    let dark =
        |x: usize, y: usize| x >= QUIET && y >= QUIET && modules.is_dark(x - QUIET, y - QUIET);

    let mut out = String::new();
    match blocks {
        Blocks::Full => {
            for y in 0..span {
                out.push_str(INK);
                for x in 0..span {
                    out.push_str(if dark(x, y) { "██" } else { "  " });
                }
                out.push_str(RESET);
                out.push('\n');
            }
        }
        Blocks::Half => {
            for pair in 0..span.div_ceil(2) {
                out.push_str(INK);
                for x in 0..span {
                    let top = dark(x, pair * 2);
                    // An odd number of rows leaves the last line with
                    // nothing underneath, and light is what belongs
                    // there — it is quiet zone either way.
                    let bottom = dark(x, pair * 2 + 1);
                    out.push(match (top, bottom) {
                        (true, true) => '█',
                        (true, false) => '▀',
                        (false, true) => '▄',
                        (false, false) => ' ',
                    });
                }
                out.push_str(RESET);
                out.push('\n');
            }
        }
    }
    out
}

impl fmt::Display for Drawing {
    /// Only the code prints itself. The narrow case is a sentence the
    /// caller builds with what it knows — the command that hands over
    /// the same config as text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Drawing::Code(text) => f.write_str(text),
            Drawing::TooNarrow { needed, available } => write!(
                f,
                "the code needs {needed} columns and this terminal has {available}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 3×3 with a dark corner at (0,0) and a dark middle — enough
    /// shape to tell rows from columns apart.
    fn tiny() -> Modules {
        Modules::new(
            3,
            vec![
                true, false, false, //
                false, true, false, //
                false, false, true,
            ],
        )
        .unwrap()
    }

    /// The characters of one drawn line, escapes stripped.
    fn ink(line: &str) -> String {
        line.trim_start_matches(INK)
            .trim_end_matches(RESET)
            .to_string()
    }

    #[test]
    fn a_grid_that_is_not_square_is_not_a_code() {
        // A length and a side that disagree would draw something that
        // looks like a QR code out of rows shifted against each other.
        assert!(Modules::new(3, vec![true; 8]).is_none());
        assert!(Modules::new(3, vec![true; 10]).is_none());
        assert!(Modules::new(0, vec![]).is_none());
        assert_eq!(Modules::new(2, vec![true; 4]).unwrap().size(), 2);
    }

    #[test]
    fn outside_the_code_is_light_so_the_quiet_zone_draws_itself() {
        // The margin and the code come out of the same loop, with
        // nothing to keep in step: every lookup past the edge is light.
        let modules = tiny();
        assert!(modules.is_dark(0, 0));
        assert!(!modules.is_dark(1, 0));
        assert!(!modules.is_dark(3, 0), "past the right edge");
        assert!(!modules.is_dark(0, 3), "past the bottom");
        assert!(!modules.is_dark(usize::MAX, usize::MAX));
    }

    #[test]
    fn the_quiet_zone_is_four_modules_on_every_side() {
        // Without it a scanner has no edge to find the code against,
        // and reports nothing rather than reporting a problem.
        assert_eq!(QUIET, 4);
        let drawn = draw_with(&tiny(), Blocks::Half);
        let lines: Vec<String> = drawn.lines().map(ink).collect();

        // 3 + 4 + 4 = 11 module rows, two to a line.
        assert_eq!(lines.len(), 6);
        // The first two lines are quiet zone, and so are the last two
        // module rows.
        assert_eq!(lines[0], " ".repeat(11));
        assert_eq!(lines[1], " ".repeat(11));
        assert_eq!(lines[5], " ".repeat(11));
        // Four light columns before the first dark module and four
        // after the last.
        let first = &lines[2];
        assert_eq!(&first[..4], "    ");
        assert_eq!(first.chars().rev().take(4).collect::<String>(), "    ");
    }

    #[test]
    fn a_module_comes_out_square_in_both_styles() {
        // A terminal cell is about twice as tall as it is wide. One
        // character per module would draw a code twice as tall as it is
        // wide; these two correct for that in opposite directions.
        let span = 3 + 2 * QUIET;
        // Two cells wide, one tall.
        assert_eq!(columns(3, Blocks::Full), span * 2);
        assert_eq!(rows(3, Blocks::Full), span);
        // One cell wide, half of one tall.
        assert_eq!(columns(3, Blocks::Half), span);
        assert_eq!(rows(3, Blocks::Half), span.div_ceil(2));

        assert_eq!(draw_with(&tiny(), Blocks::Full).lines().count(), span);
        assert_eq!(
            draw_with(&tiny(), Blocks::Half).lines().count(),
            span.div_ceil(2)
        );
    }

    #[test]
    fn two_module_rows_share_a_line_in_the_compact_style() {
        let drawn = draw_with(&tiny(), Blocks::Half);
        let lines: Vec<String> = drawn.lines().map(ink).collect();

        // Module rows 4 and 5 of the padded grid: the code's rows 0 and
        // 1, dark at x=4 and x=5 respectively.
        let paired = &lines[2];
        assert_eq!(paired.chars().nth(4), Some('▀'), "dark above only");
        assert_eq!(paired.chars().nth(5), Some('▄'), "dark below only");
        assert_eq!(paired.chars().nth(6), Some(' '), "neither");

        // A column dark in both rows is one full block.
        let both = Modules::new(2, vec![true, false, true, false]).unwrap();
        let line = ink(draw_with(&both, Blocks::Half).lines().nth(2).unwrap());
        assert_eq!(line.chars().nth(4), Some('█'));
    }

    #[test]
    fn an_odd_number_of_module_rows_still_fits_in_whole_lines() {
        // 4 + 4 + 4 = 12 rows is even; a code of odd size is not, and
        // the last line has nothing underneath it. Light belongs there
        // — it is quiet zone either way — and dropping the line would
        // eat a module row.
        let odd = Modules::new(1, vec![true]).unwrap();
        assert_eq!(1 + 2 * QUIET, 9, "an odd number of module rows");
        let lines: Vec<String> = draw_with(&odd, Blocks::Half).lines().map(ink).collect();
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[4], " ".repeat(9), "the half-empty last line");
        // The one dark module lands in padded row 4, the top half of
        // the third line.
        assert_eq!(lines[2].chars().nth(4), Some('▀'), "row 4 of 0..9");
    }

    #[test]
    fn the_code_says_which_way_round_it_is() {
        // On a dark-theme terminal `█` is the *light* square, so a code
        // drawn with characters alone comes out inverted — and an
        // inverted code is not something every scanner reads.
        for blocks in [Blocks::Full, Blocks::Half] {
            let drawn = draw_with(&tiny(), blocks);
            for line in drawn.lines() {
                assert!(line.starts_with(INK), "{line:?}");
                assert!(line.ends_with(RESET), "{line:?}");
            }
            // Black on white, and reset at the end of every line so a
            // half-copied code does not leave the session painted.
            assert!(INK.contains("30"), "black ink");
            assert!(INK.contains("47"), "white ground");
            assert_eq!(drawn.matches(INK).count(), drawn.lines().count());
            assert_eq!(drawn.matches(RESET).count(), drawn.lines().count());
        }
    }

    #[test]
    fn the_wider_style_is_used_wherever_it_fits() {
        // It draws bigger, and it draws with characters every terminal
        // font has — half blocks are what a sparse font gets wrong, and
        // a missing glyph in a QR code is a code that does not scan.
        let span = 3 + 2 * QUIET;
        assert_eq!(fit(3, span * 2), Some(Blocks::Full));
        assert_eq!(fit(3, span * 2 + 40), Some(Blocks::Full));
        assert_eq!(fit(3, span * 2 - 1), Some(Blocks::Half));
        assert_eq!(fit(3, span), Some(Blocks::Half));
        assert_eq!(fit(3, span - 1), None);

        // The size a real config comes out at: version 12-ish. Wide
        // needs more than 80 columns; compact fits.
        let real = 65;
        assert!(columns(real, Blocks::Full) > 80);
        assert!(columns(real, Blocks::Half) <= 80);
        assert_eq!(fit(real, 80), Some(Blocks::Half));
        assert_eq!(fit(real, 200), Some(Blocks::Full));
    }

    #[test]
    fn a_terminal_too_narrow_for_the_code_is_told_so_and_not_drawn() {
        // A QR wider than the terminal wraps, and a wrapped QR still
        // looks like a QR — it just cannot be read, and the person
        // finds that out by holding a phone up to it.
        let drawing = draw(&tiny(), 4);
        assert_eq!(
            drawing,
            Drawing::TooNarrow {
                needed: 3 + 2 * QUIET,
                available: 4,
            }
        );
        assert!(!drawing.to_string().contains('█'), "nothing was drawn");
        assert!(
            drawing.to_string().contains("needs 11 columns"),
            "{drawing}"
        );

        // And every line of a code that *was* drawn fits.
        let Drawing::Code(text) = draw(&tiny(), 11) else {
            panic!("11 columns is enough for the compact style");
        };
        for line in text.lines() {
            assert!(ink(line).chars().count() <= 11, "{line:?}");
        }
    }

    #[test]
    fn every_line_of_a_drawing_is_as_wide_as_it_claims() {
        // The one property a wrapped code violates, checked for both
        // styles and for a size that pads to an odd number of rows.
        for size in [1, 2, 3, 21] {
            let modules = Modules::new(size, vec![true; size * size]).unwrap();
            for blocks in [Blocks::Full, Blocks::Half] {
                let drawn = draw_with(&modules, blocks);
                assert_eq!(
                    drawn.lines().count(),
                    rows(size, blocks),
                    "{size} {blocks:?}"
                );
                for line in drawn.lines() {
                    assert_eq!(
                        ink(line).chars().count(),
                        columns(size, blocks),
                        "{size} {blocks:?}: {line:?}"
                    );
                }
                assert!(drawn.ends_with('\n'), "{size} {blocks:?}");
            }
        }
    }
}
