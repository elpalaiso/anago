//! One field out of a certificate: `notAfter` (DESIGN.md §9.1).
//!
//! §10.2 keeps `x509-parser` out — it is for ARI and it brings a dozen
//! ASN.1 crates with it. What is needed here is smaller than a parser:
//! the binary already turns PEM into DER with `rustls-pemfile`, and the
//! path from there to the expiry is fixed by RFC 5280 —
//! `Certificate` → `TBSCertificate` → `Validity` → the second `Time`.
//!
//! **Nothing here decides whether to trust anything.** rustls verifies
//! certificates (§7); this value is used for the renewal schedule and
//! for telling a person when their certificate runs out. So it is
//! written to fail quietly: anything unexpected reads as `None`, the
//! renewal falls back to §9.1's assumed lifetime, and the worst a bug
//! in this file can do is fail to print a date.

/// The `notAfter` of a DER-encoded certificate, in epoch seconds.
///
/// `None` when the bytes are not a certificate, or the time is in a
/// form RFC 5280 does not allow. Never an error and never a panic —
/// see the module note.
pub fn not_after(der: &[u8]) -> Option<i64> {
    let mut outer = Der::new(der);
    let certificate = outer.expect(SEQUENCE)?;
    let mut inside = Der::new(certificate);
    let mut fields = Der::new(inside.expect(SEQUENCE)?);

    // version [0] EXPLICIT, and absent in a v1 certificate — which is
    // why the first field has to be looked at rather than skipped.
    let (mut tag, _) = fields.next()?;
    if tag == VERSION {
        (tag, _) = fields.next()?;
    }
    // serialNumber. Checked rather than skipped: if this is not an
    // INTEGER the walk is already lost, and reading a "time" out of
    // whatever comes next would produce a confident wrong date.
    if tag != INTEGER {
        return None;
    }
    fields.expect(SEQUENCE)?; // signature AlgorithmIdentifier
    fields.expect(SEQUENCE)?; // issuer Name

    let mut validity = Der::new(fields.expect(SEQUENCE)?);
    validity.next()?; // notBefore
    let (tag, text) = validity.next()?;
    time(tag, text)
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
/// `[0]` constructed — the context tag the optional `version` wears.
const VERSION: u8 = 0xA0;
/// `YYMMDDHHMMSSZ`.
const UTC_TIME: u8 = 0x17;
/// `YYYYMMDDHHMMSSZ`.
const GENERALIZED_TIME: u8 = 0x18;

/// A cursor over a sequence of DER elements.
struct Der<'a> {
    bytes: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(bytes: &'a [u8]) -> Der<'a> {
        Der { bytes }
    }

    /// The next element's tag and contents, moving past it.
    ///
    /// DER only: lengths are definite and encoded in as few bytes as
    /// the value allows. The indefinite form (`0x80`) is legal BER and
    /// not legal here, and it falls out of the length check below
    /// rather than needing a case of its own.
    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = self.bytes.split_first()?;
        let (&first, rest) = rest.split_first()?;
        let (length, rest) = if first < 0x80 {
            (first as usize, rest)
        } else {
            // Four length bytes is a certificate of four gigabytes;
            // anything asking for more is not one.
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 || rest.len() < count {
                return None;
            }
            let (bytes, rest) = rest.split_at(count);
            (
                bytes.iter().fold(0usize, |n, b| (n << 8) | usize::from(*b)),
                rest,
            )
        };
        if rest.len() < length {
            return None;
        }
        let (contents, after) = rest.split_at(length);
        self.bytes = after;
        Some((tag, contents))
    }

    /// The next element, when it is the tag expected there.
    fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        let (found, contents) = self.next()?;
        (found == tag).then_some(contents)
    }
}

/// An X.509 `Time`, in either of the two forms RFC 5280 §4.1.2.5
/// allows.
///
/// Both are required to end in `Z` and to carry seconds, so the two
/// lengths are exact. Anything else — a local offset, a fractional
/// second, a two-digit year in a `GeneralizedTime` — is a certificate
/// this reader declines to guess about.
fn time(tag: u8, text: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(text).ok()?;
    let (year, rest) = match tag {
        UTC_TIME if text.len() == 13 => {
            let short = number(text, 0)?;
            // RFC 5280 §4.1.2.5.1: 50 and above is 19xx. A certificate
            // that expires before 1950 or after 2049 has to use the
            // other form, which is why this window is not a guess.
            let year = if short >= 50 {
                1900 + short
            } else {
                2000 + short
            };
            (year, &text[2..])
        }
        GENERALIZED_TIME if text.len() == 15 => {
            (number(text, 0)? * 100 + number(text, 2)?, &text[4..])
        }
        _ => return None,
    };
    if !rest.ends_with('Z') {
        return None;
    }

    let month = number(rest, 0)?;
    let day = number(rest, 2)?;
    let hour = number(rest, 4)?;
    let minute = number(rest, 6)?;
    let second = number(rest, 8)?;
    // The day is checked against the month it is in, not against 31.
    // `days_from_civil` is arithmetic and has no opinion: it turns a
    // February the 31st into the 3rd of March and hands back an epoch
    // that looks entirely reasonable. That is the one outcome this
    // module must not have — a date nobody can tell is wrong, printed
    // as a fact and used to schedule a renewal.
    //
    // A leap second (60) is allowed through rather than refused: it is
    // a real value in the encoding, and a second either way changes
    // nothing here.
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }

    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

/// How many days that month has, in that year.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// The Gregorian leap rule, all three parts of it. Two of them only
/// differ once a century, which is exactly why they are written down
/// rather than assumed.
fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Two ASCII digits at `at`.
///
/// Digits only: `str::parse` would accept `"+1"` and `" 1"`, and a
/// certificate with either is not one to read a date out of.
fn number(text: &str, at: usize) -> Option<i64> {
    let pair = text.get(at..at + 2)?;
    if !pair.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    pair.parse().ok()
}

/// Days from 1970-01-01 to `y-m-d` in the proleptic Gregorian
/// calendar.
///
/// Howard Hinnant's `days_from_civil`: integers only, exact for leap
/// years and for the century rule, and no calendar library anywhere
/// near it (§10.1 keeps date handling out of core, and this is
/// arithmetic rather than date handling).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    // March-based years, so that the leap day is the last day of one.
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DER element: tag, then a definite length, then contents.
    fn element(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if contents.len() < 0x80 {
            out.push(contents.len() as u8);
        } else {
            let bytes = (contents.len() as u32).to_be_bytes();
            let start = bytes.iter().position(|b| *b != 0).unwrap();
            out.push(0x80 | (4 - start) as u8);
            out.extend_from_slice(&bytes[start..]);
        }
        out.extend_from_slice(contents);
        out
    }

    /// A certificate with just enough structure to reach the expiry:
    /// everything before `validity` is present and the right shape,
    /// everything after it is what a real one carries and this reader
    /// never looks at.
    fn certificate(version: bool, not_before: &[u8], not_after: &[u8]) -> Vec<u8> {
        let mut tbs = Vec::new();
        if version {
            tbs.extend(element(VERSION, &element(INTEGER, &[2])));
        }
        tbs.extend(element(INTEGER, &[0x0b, 0xad, 0xf0, 0x0d]));
        tbs.extend(element(SEQUENCE, b"algorithm")); // signature
        tbs.extend(element(SEQUENCE, b"issuer"));
        let mut validity = Vec::new();
        validity.extend_from_slice(not_before);
        validity.extend_from_slice(not_after);
        tbs.extend(element(SEQUENCE, &validity));
        tbs.extend(element(SEQUENCE, b"subject"));

        let mut certificate = element(SEQUENCE, &tbs);
        certificate.extend(element(SEQUENCE, b"signatureAlgorithm"));
        certificate.extend(element(0x03, b"signature"));
        element(SEQUENCE, &certificate)
    }

    fn utc(text: &str) -> Vec<u8> {
        element(UTC_TIME, text.as_bytes())
    }

    fn generalized(text: &str) -> Vec<u8> {
        element(GENERALIZED_TIME, text.as_bytes())
    }

    #[test]
    fn reads_a_utc_time_expiry() {
        // 2026-11-17T01:02:03Z.
        let der = certificate(true, &utc("260101000000Z"), &utc("261117010203Z"));
        assert_eq!(not_after(&der), Some(1_794_877_323));
    }

    #[test]
    fn reads_a_generalized_time_expiry() {
        // The form a certificate has to use past 2049 — and the one
        // the throwaway fixtures in this repo happen to carry.
        let der = certificate(
            true,
            &generalized("20260101000000Z"),
            &generalized("21260726010331Z"),
        );
        assert_eq!(not_after(&der), Some(4_940_701_411));
    }

    #[test]
    fn the_two_digit_year_window_is_the_one_rfc_5280_fixes() {
        // 50..=99 is 19xx, 00..=49 is 20xx. A certificate outside that
        // window has to use GeneralizedTime, so there is no case where
        // this has to guess.
        let epoch = |text: &str| not_after(&certificate(true, &utc("700101000000Z"), &utc(text)));
        assert_eq!(epoch("700101000000Z"), Some(0), "1970 is the epoch itself");
        assert_eq!(epoch("491231235959Z"), Some(2_524_607_999), "2049");
        assert_eq!(epoch("500101000000Z"), Some(-631_152_000), "1950, not 2050");
    }

    #[test]
    fn a_v1_certificate_has_no_version_field() {
        // The field is OPTIONAL with a DEFAULT, so DER leaves it out —
        // and then the first element is the serial number. Skipping a
        // fixed number of fields would read the issuer as the validity.
        let der = certificate(false, &utc("260101000000Z"), &utc("261117010203Z"));
        assert_eq!(not_after(&der), Some(1_794_877_323));
    }

    #[test]
    fn leap_days_and_century_years_come_out_right() {
        // The two dates a hand-rolled calendar gets wrong: the leap day
        // of a century that is a leap year, and the one that is not.
        let at = |text: &str| {
            not_after(&certificate(
                true,
                &utc("700101000000Z"),
                &generalized(text),
            ))
        };
        // 2000 is a leap year (divisible by 400).
        assert_eq!(at("20000229000000Z"), Some(951_782_400));
        // 2100 is not (divisible by 100 and not by 400), so the 29th
        // does not exist and the 28th is the last of February.
        assert_eq!(at("21000228000000Z"), Some(4_107_456_000));
        assert_eq!(at("21000301000000Z"), Some(4_107_542_400));
    }

    #[test]
    fn a_long_form_length_is_read() {
        // Real certificates are longer than 127 bytes, so every one of
        // them exercises this; the short-form fixtures above do not.
        let padding = vec![0x41; 300];
        let mut tbs = Vec::new();
        tbs.extend(element(INTEGER, &[1]));
        tbs.extend(element(SEQUENCE, &padding));
        tbs.extend(element(SEQUENCE, &padding));
        let mut validity = utc("260101000000Z");
        validity.extend(utc("261117010203Z"));
        tbs.extend(element(SEQUENCE, &validity));
        let der = element(SEQUENCE, &element(SEQUENCE, &tbs));
        assert_eq!(not_after(&der), Some(1_794_877_323));
    }

    #[test]
    fn anything_that_is_not_a_certificate_reads_as_no_date() {
        // Failing quietly is the contract: the renewal then runs on
        // §9.1's assumed lifetime, and the display says it could not
        // read the date. A confident wrong answer is the one outcome
        // that would matter.
        assert_eq!(not_after(b""), None);
        assert_eq!(not_after(b"-----BEGIN CERTIFICATE-----"), None);
        assert_eq!(
            not_after(&[0x30, 0x82, 0xff, 0xff]),
            None,
            "a length past the end"
        );
        assert_eq!(not_after(&element(SEQUENCE, b"")), None);
        // A structure that walks but ends somewhere that is not a time.
        assert_eq!(
            not_after(&certificate(
                true,
                &utc("260101000000Z"),
                &element(INTEGER, &[7])
            )),
            None
        );
    }

    #[test]
    fn a_time_that_is_not_the_shape_rfc_5280_requires_is_refused() {
        let expiry = |time: Vec<u8>| not_after(&certificate(true, &utc("260101000000Z"), &time));
        // No seconds.
        assert_eq!(expiry(utc("2611170102Z")), None);
        // A local offset rather than Z — legal in BER, not in RFC 5280.
        assert_eq!(expiry(utc("261117010203+0900")), None);
        // Two-digit year in the four-digit form.
        assert_eq!(expiry(generalized("261117010203Z")), None);
        // Digits only: `parse` alone would take these.
        assert_eq!(expiry(utc("2611170102 3Z")), None);
        assert_eq!(expiry(utc("26111701+203Z")), None);
        // Out of range.
        assert_eq!(expiry(utc("261317010203Z")), None, "month 13");
        assert_eq!(expiry(utc("261100010203Z")), None, "day 0");
        assert_eq!(expiry(utc("261117250203Z")), None, "hour 25");
    }

    #[test]
    fn a_day_that_does_not_exist_is_not_normalised_into_one_that_does() {
        // The arithmetic underneath has no opinion: it turns February
        // the 31st into the 3rd of March and returns an epoch that
        // looks perfectly ordinary. A wrong date nobody can tell is
        // wrong — printed as fact, and used to schedule the renewal —
        // is the one thing this module must not produce.
        let expiry = |text: &str| not_after(&certificate(true, &utc("700101000000Z"), &utc(text)));
        assert_eq!(expiry("260231000000Z"), None, "31 February");
        assert_eq!(expiry("260230000000Z"), None, "30 February");
        assert_eq!(expiry("260431000000Z"), None, "31 April");
        assert_eq!(expiry("260631000000Z"), None, "31 June");
        assert_eq!(expiry("260931000000Z"), None, "31 September");
        assert_eq!(expiry("261131000000Z"), None, "31 November");
        // And the days that do exist still do.
        assert!(expiry("260131000000Z").is_some(), "31 January");
        assert!(expiry("260430000000Z").is_some(), "30 April");
        assert!(
            expiry("261231235959Z").is_some(),
            "the last second of a year"
        );
    }

    #[test]
    fn the_leap_day_exists_exactly_when_the_gregorian_rule_says() {
        // The two century cases are where a hand-rolled rule goes
        // wrong, and a certificate is entitled to expire on either.
        let expiry = |text: &str| {
            not_after(&certificate(
                true,
                &utc("700101000000Z"),
                &generalized(text),
            ))
        };
        assert!(expiry("20240229000000Z").is_some(), "2024 is a leap year");
        assert!(expiry("20260229000000Z").is_none(), "2026 is not");
        assert!(
            expiry("20000229000000Z").is_some(),
            "2000: divisible by 400"
        );
        assert!(
            expiry("21000229000000Z").is_none(),
            "2100: by 100, not by 400"
        );
        assert!(expiry("24000229000000Z").is_some(), "2400: by 400 again");
    }

    #[test]
    fn the_serial_number_has_to_be_where_it_belongs() {
        // Regression risk: walking a structure by counting fields. If
        // the first element is neither a version tag nor an integer,
        // the walk is lost and every field after it is misread — so it
        // stops rather than reporting whatever it lands on.
        let mut tbs = element(SEQUENCE, b"not a serial number");
        tbs.extend(element(SEQUENCE, b"algorithm"));
        tbs.extend(element(SEQUENCE, b"issuer"));
        let mut validity = utc("260101000000Z");
        validity.extend(utc("261117010203Z"));
        tbs.extend(element(SEQUENCE, &validity));
        let der = element(SEQUENCE, &element(SEQUENCE, &tbs));
        assert_eq!(not_after(&der), None);
    }
}
