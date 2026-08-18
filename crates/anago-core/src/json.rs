//! Minimal JSON for anago's own protocol types and server state file
//! (DESIGN.md §10.1 — serde is deliberately not used; the schema's
//! source of truth lives here in pure std).
//!
//! The supported surface is deliberately narrow, matching §10.1:
//!
//! - values: object, array, string, integer, bool, null. **No floats**
//!   — a `.`/`e` in a number is a parse error, not a silent cast.
//! - integers are `i64`; anything outside that range is an error.
//! - objects keep declaration order, so output is deterministic.
//! - duplicate keys are always an error, never a silent last-wins:
//!   [`parse`] rejects repeated keys, and on the construction side
//!   [`Object::insert`] refuses to overwrite.
//! - `to_string` is compact (API bodies), `to_string_pretty` uses two
//!   spaces (the state file, which a human may open and edit).

use std::fmt;

/// Maximum nesting depth accepted by [`parse`]. The server parses
/// request bodies from the network; a bound keeps hostile nesting from
/// blowing the stack. anago's own schemas nest three levels deep.
const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Value>),
    Obj(Object),
}

/// A JSON object: key/value pairs in insertion order, which is the
/// order they serialize in.
///
/// The pairs are private, and the only way in — [`Object::insert`] —
/// refuses a key that is already present. So an `Object` can never hold
/// two `"name"` entries, and `to_string` can never emit a document
/// [`parse`] would reject: `parse(to_string(&v)) == v` holds for every
/// value this module can build.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Object(Vec<(String, Value)>);

impl Object {
    pub fn new() -> Object {
        Object(Vec::new())
    }

    /// Adds a field. A key already present is an error — DESIGN.md
    /// §10.1 forbids quietly adopting the last value, so an accidental
    /// second `"address"` fails here instead of dropping a field on the
    /// floor.
    pub fn insert(&mut self, key: impl Into<String>, value: Value) -> Result<(), DuplicateKey> {
        let key = key.into();
        if self.get(&key).is_some() {
            return Err(DuplicateKey { key });
        }
        self.0.push((key, value));
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<const N: usize> TryFrom<[(&str, Value); N]> for Object {
    type Error = DuplicateKey;

    fn try_from(pairs: [(&str, Value); N]) -> Result<Object, DuplicateKey> {
        let mut obj = Object::new();
        for (key, value) in pairs {
            obj.insert(key, value)?;
        }
        Ok(obj)
    }
}

/// Rejected because the key was already in the object.
#[derive(Debug, Clone, PartialEq)]
pub struct DuplicateKey {
    pub key: String,
}

impl fmt::Display for DuplicateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "duplicate key {:?}", self.key)
    }
}

impl std::error::Error for DuplicateKey {}

impl Value {
    /// Builds an object from literal pairs, rejecting a repeated key.
    pub fn try_obj<const N: usize>(pairs: [(&str, Value); N]) -> Result<Value, DuplicateKey> {
        Object::try_from(pairs).map(Value::Obj)
    }

    /// [`Value::try_obj`] for call sites that write the keys out
    /// literally, where a repeat is a typo in this repository rather
    /// than bad input.
    ///
    /// # Panics
    ///
    /// If `pairs` repeats a key. Loud at the first test run that touches
    /// the line — the one thing it will not do is silently drop a field.
    pub fn obj<const N: usize>(pairs: [(&str, Value); N]) -> Value {
        Value::try_obj(pairs).unwrap_or_else(|e| panic!("{e}"))
    }

    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }

    /// Field lookup on an object; `None` for a missing key or a
    /// non-object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(obj) => obj.get(key),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Arr(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Obj(obj) => Some(obj),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
}

/// A parse failure: what went wrong and the byte offset it was noticed
/// at. Byte offsets (not char indexes) so they line up with the input
/// slice the caller holds.
#[derive(Debug, Clone, PartialEq)]
pub struct Error {
    pub msg: String,
    pub offset: usize,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at byte {})", self.msg, self.offset)
    }
}

impl std::error::Error for Error {}

// ---------------------------------------------------------------- write

/// Compact form — no whitespace. Used for API request/response bodies.
pub fn to_string(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, None, 0, &mut out);
    out
}

/// Two-space indented form. Used for `state.json`, which DESIGN.md §9
/// says a human should be able to read and hand-edit.
pub fn to_string_pretty(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, Some(2), 0, &mut out);
    out
}

fn write_value(value: &Value, indent: Option<usize>, depth: usize, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(n) => out.push_str(&n.to_string()),
        Value::Str(s) => write_string(s, out),
        Value::Arr(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_break(indent, depth + 1, out);
                write_value(item, indent, depth + 1, out);
            }
            write_break(indent, depth, out);
            out.push(']');
        }
        Value::Obj(obj) => {
            if obj.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (key, val)) in obj.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_break(indent, depth + 1, out);
                write_string(key, out);
                out.push(':');
                if indent.is_some() {
                    out.push(' ');
                }
                write_value(val, indent, depth + 1, out);
            }
            write_break(indent, depth, out);
            out.push('}');
        }
    }
}

fn write_break(indent: Option<usize>, depth: usize, out: &mut String) {
    if let Some(step) = indent {
        out.push('\n');
        for _ in 0..step * depth {
            out.push(' ');
        }
    }
}

/// Escapes only what JSON requires: quote, backslash, and control
/// characters below 0x20 (the short forms where they exist, `\u00XX`
/// otherwise). Everything else — including non-ASCII — goes out as
/// UTF-8, so Korean device names stay readable in `state.json`.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---------------------------------------------------------------- read

/// Parses a complete JSON document. Trailing content after the value
/// (other than whitespace) is an error — a truncated-then-appended
/// state file should fail loudly, not parse halfway.
pub fn parse(input: &str) -> Result<Value, Error> {
    let mut p = Parser {
        b: input.as_bytes(),
        i: 0,
    };
    p.skip_ws();
    let value = p.value(0)?;
    p.skip_ws();
    if p.i < p.b.len() {
        return Err(p.err("trailing content after JSON value"));
    }
    Ok(value)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn err(&self, msg: &str) -> Error {
        Error {
            msg: msg.to_string(),
            offset: self.i,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn expect(&mut self, c: u8) -> Result<(), Error> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(self.err(&format!("expected '{}'", c as char)))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting too deep"));
        }
        match self.peek() {
            None => Err(self.err("unexpected end of input")),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::Str),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(_) => Err(self.err("unexpected character")),
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, Error> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(value)
        } else {
            Err(self.err("invalid literal"))
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, Error> {
        self.expect(b'{')?;
        let mut obj = Object::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Obj(obj));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected object key"));
            }
            let key_at = self.i;
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value(depth + 1)?;
            // `insert` owns the no-duplicates rule; this only attaches
            // the byte offset of the offending key to it.
            obj.insert(key, value).map_err(|e| Error {
                msg: e.to_string(),
                offset: key_at,
            })?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Obj(obj));
                }
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, Error> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Arr(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Arr(items));
                }
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
    }

    fn string(&mut self) -> Result<String, Error> {
        self.expect(b'"')?;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let c = match self.peek() {
                Some(c) => c,
                None => return Err(self.err("unterminated string")),
            };
            match c {
                b'"' => {
                    self.i += 1;
                    return String::from_utf8(buf).map_err(|_| self.err("invalid UTF-8 in string"));
                }
                b'\\' => {
                    self.i += 1;
                    let esc = self.peek().ok_or_else(|| self.err("unterminated escape"))?;
                    self.i += 1;
                    match esc {
                        b'"' => buf.push(b'"'),
                        b'\\' => buf.push(b'\\'),
                        b'/' => buf.push(b'/'),
                        b'b' => buf.push(0x08),
                        b'f' => buf.push(0x0c),
                        b'n' => buf.push(b'\n'),
                        b'r' => buf.push(b'\r'),
                        b't' => buf.push(b'\t'),
                        b'u' => {
                            let decoded = self.unicode_escape()?;
                            let mut tmp = [0u8; 4];
                            buf.extend_from_slice(decoded.encode_utf8(&mut tmp).as_bytes());
                        }
                        _ => return Err(self.err("invalid escape")),
                    }
                }
                c if c < 0x20 => return Err(self.err("unescaped control character in string")),
                c => {
                    buf.push(c);
                    self.i += 1;
                }
            }
        }
    }

    /// Reads the four hex digits after `\u`, joining a surrogate pair
    /// with its low mate. A lone surrogate is an error — it has no
    /// UTF-8 encoding, and Rust strings are UTF-8.
    fn unicode_escape(&mut self) -> Result<char, Error> {
        let first = self.hex4()?;
        let code = match first {
            0xD800..=0xDBFF => {
                if !(self.peek() == Some(b'\\') && self.b.get(self.i + 1) == Some(&b'u')) {
                    return Err(self.err("lone high surrogate in \\u escape"));
                }
                self.i += 2;
                let low = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(self.err("invalid low surrogate in \\u escape"));
                }
                0x10000 + ((first - 0xD800) << 10) + (low - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(self.err("lone low surrogate in \\u escape")),
            other => other,
        };
        char::from_u32(code).ok_or_else(|| self.err("invalid code point in \\u escape"))
    }

    fn hex4(&mut self) -> Result<u32, Error> {
        let end = self.i + 4;
        if end > self.b.len() {
            return Err(self.err("truncated \\u escape"));
        }
        let mut value = 0u32;
        for &c in &self.b[self.i..end] {
            let digit = match c {
                b'0'..=b'9' => u32::from(c - b'0'),
                b'a'..=b'f' => u32::from(c - b'a') + 10,
                b'A'..=b'F' => u32::from(c - b'A') + 10,
                _ => return Err(self.err("invalid hex digit in \\u escape")),
            };
            value = value * 16 + digit;
        }
        self.i = end;
        Ok(value)
    }

    /// Integers only. A fractional or exponent part is rejected rather
    /// than rounded — DESIGN.md §10.1 keeps floats out of the schema,
    /// and silently truncating a `1.5` would be worse than failing.
    fn number(&mut self) -> Result<Value, Error> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let digits_start = self.i;
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
        }
        if self.i == digits_start {
            return Err(self.err("expected digits in number"));
        }
        if self.b[digits_start] == b'0' && self.i - digits_start > 1 {
            return Err(Error {
                msg: "leading zero in number".to_string(),
                offset: digits_start,
            });
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(self.err("floats are not supported"));
        }
        let text =
            std::str::from_utf8(&self.b[start..self.i]).map_err(|_| self.err("invalid number"))?;
        text.parse::<i64>().map(Value::Int).map_err(|_| Error {
            msg: "integer out of i64 range".to_string(),
            offset: start,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_like() -> Value {
        Value::obj([
            ("version", Value::Int(1)),
            ("domain", Value::str("net.example.com")),
            ("listen_port", Value::Int(51820)),
            (
                "server",
                Value::obj([
                    ("public_key", Value::str("K1+abc/def=")),
                    ("address", Value::str("10.100.0.1")),
                ]),
            ),
            (
                "peers",
                Value::Arr(vec![Value::obj([
                    ("name", Value::str("맥북")),
                    ("created_at", Value::Int(1755500000)),
                    ("last_seen", Value::Null),
                    ("enabled", Value::Bool(true)),
                ])]),
            ),
            ("codes", Value::Arr(vec![])),
        ])
    }

    // -------------------------------------------------------- writing

    #[test]
    fn writes_scalars() {
        assert_eq!(to_string(&Value::Null), "null");
        assert_eq!(to_string(&Value::Bool(true)), "true");
        assert_eq!(to_string(&Value::Bool(false)), "false");
        assert_eq!(to_string(&Value::Int(0)), "0");
        assert_eq!(to_string(&Value::Int(-51820)), "-51820");
        assert_eq!(to_string(&Value::Int(i64::MIN)), i64::MIN.to_string());
    }

    #[test]
    fn escapes_only_what_json_requires() {
        let v = Value::str("q\"b\\s/ n\nr\rt\tbell\u{07}back\u{08}ff\u{0c}");
        // Expected form spelled with escapes so no raw control byte can
        // sneak into this literal.
        let expected = concat!("\"q\\\"b\\\\s/ n\\nr\\rt\\tbell", "\\u0007back\\bff\\f\"");
        assert_eq!(to_string(&v), expected);
    }

    #[test]
    fn leaves_non_ascii_as_utf8() {
        // Korean device names must stay readable in state.json.
        assert_eq!(to_string(&Value::str("맥북 🐟")), "\"맥북 🐟\"");
    }

    #[test]
    fn key_order_is_declaration_order_not_sorted() {
        let v = Value::obj([
            ("version", Value::Int(1)),
            ("angle", Value::Int(2)),
            ("domain", Value::Int(3)),
        ]);
        assert_eq!(to_string(&v), r#"{"version":1,"angle":2,"domain":3}"#);
        // Same input, same bytes — every time.
        assert_eq!(to_string(&v), to_string(&v.clone()));
    }

    #[test]
    fn writes_empty_containers_inline() {
        assert_eq!(to_string(&Value::Arr(vec![])), "[]");
        assert_eq!(to_string(&Value::Obj(Object::new())), "{}");
        assert_eq!(to_string_pretty(&Value::Arr(vec![])), "[]");
        assert_eq!(
            to_string_pretty(&Value::obj([("codes", Value::Arr(vec![]))])),
            "{\n  \"codes\": []\n}"
        );
    }

    #[test]
    fn pretty_uses_two_space_indent() {
        let v = Value::obj([
            ("version", Value::Int(1)),
            (
                "peers",
                Value::Arr(vec![Value::obj([("name", Value::str("macbook"))])]),
            ),
        ]);
        let expected =
            "{\n  \"version\": 1,\n  \"peers\": [\n    {\n      \"name\": \"macbook\"\n    }\n  ]\n}";
        assert_eq!(to_string_pretty(&v), expected);
    }

    #[test]
    fn building_rejects_a_duplicate_key() {
        let e = Value::try_obj([
            ("name", Value::str("first")),
            ("address", Value::str("10.100.0.2")),
            ("name", Value::str("second")),
        ])
        .expect_err("a repeated key must not build an object");
        assert_eq!(
            e,
            DuplicateKey {
                key: "name".to_string()
            }
        );
        assert_eq!(e.to_string(), "duplicate key \"name\"");
    }

    #[test]
    #[should_panic(expected = "duplicate key \"name\"")]
    fn obj_panics_on_a_duplicate_key() {
        // The infallible literal builder must be loud, never lossy.
        Value::obj([
            ("name", Value::str("first")),
            ("name", Value::str("second")),
        ]);
    }

    #[test]
    fn insert_refuses_to_overwrite_and_keeps_order() {
        let mut obj = Object::new();
        assert!(obj.is_empty());
        assert_eq!(obj.insert("version", Value::Int(1)), Ok(()));
        assert_eq!(obj.insert("domain", Value::str("net.example.com")), Ok(()));
        assert_eq!(
            obj.insert("version", Value::Int(2)),
            Err(DuplicateKey {
                key: "version".to_string()
            })
        );
        // The rejected insert changed nothing.
        assert_eq!(obj.get("version"), Some(&Value::Int(1)));
        assert_eq!(obj.len(), 2);
        assert_eq!(
            obj.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            ["version", "domain"]
        );
    }

    #[test]
    fn every_object_this_module_can_build_round_trips() {
        // The point of refusing duplicates on the way in: `to_string`
        // can never produce a document `parse` refuses.
        let v = Value::try_obj([
            ("name", Value::str("맥북")),
            ("address", Value::str("10.100.0.2")),
        ])
        .unwrap();
        assert_eq!(parse(&to_string(&v)).unwrap(), v);
    }

    // ---------------------------------------------------- round trips

    #[test]
    fn round_trips_value_through_compact_and_pretty() {
        let v = state_like();
        assert_eq!(parse(&to_string(&v)).unwrap(), v);
        assert_eq!(parse(&to_string_pretty(&v)).unwrap(), v);
    }

    #[test]
    fn round_trips_text_back_to_identical_text() {
        let text = r#"{"a":1,"b":[true,false,null],"c":{"d":"x"},"e":-2,"f":[],"g":{}}"#;
        let parsed = parse(text).unwrap();
        assert_eq!(to_string(&parsed), text);
    }

    #[test]
    fn round_trips_strings_needing_escapes() {
        for s in [
            "",
            "plain",
            "quote\" backslash\\ slash/",
            "control\u{01}\u{1f}",
            "newline\ntab\t",
            "맥북-데스크톱",
            "emoji 🐟 outside the BMP",
        ] {
            let v = Value::str(s);
            assert_eq!(parse(&to_string(&v)).unwrap(), v, "failed for {s:?}");
        }
    }

    #[test]
    fn round_trips_integer_bounds() {
        for n in [0, 1, -1, i64::MAX, i64::MIN] {
            let v = Value::Int(n);
            assert_eq!(parse(&to_string(&v)).unwrap(), v);
        }
    }

    // -------------------------------------------------------- reading

    #[test]
    fn accepts_whitespace_and_known_escapes() {
        assert_eq!(
            parse("  {\n\t\"a\" : [ 1 , 2 ]\r\n}  ").unwrap(),
            Value::obj([("a", Value::Arr(vec![Value::Int(1), Value::Int(2)]))])
        );
        assert_eq!(parse(r#""A\/\b""#).unwrap(), Value::str("A/\u{08}"));
        // Surrogate pair for U+1F41F.
        assert_eq!(parse(r#""🐟""#).unwrap(), Value::str("🐟"));
    }

    #[test]
    fn accessors_read_fields() {
        let v = state_like();
        assert_eq!(
            v.get("domain").and_then(Value::as_str),
            Some("net.example.com")
        );
        assert_eq!(v.get("version").and_then(Value::as_i64), Some(1));
        assert_eq!(v.get("nope"), None);
        assert_eq!(
            v.get("codes").and_then(Value::as_array).map(<[_]>::len),
            Some(0)
        );
        let peer = &v.get("peers").unwrap().as_array().unwrap()[0];
        assert_eq!(peer.get("name").and_then(Value::as_str), Some("맥북"));
        assert!(peer.get("last_seen").unwrap().is_null());
        assert_eq!(peer.get("enabled").and_then(Value::as_bool), Some(true));
        assert_eq!(v.as_object().map(Object::len), Some(6));
        // Wrong-type accessors say no rather than guessing.
        assert_eq!(v.get("version").and_then(Value::as_str), None);
        assert_eq!(Value::Int(1).get("version"), None);
    }

    // ----------------------------------------------------- error cases

    fn err(input: &str) -> String {
        parse(input).expect_err("should have failed").msg
    }

    #[test]
    fn rejects_floats_rather_than_truncating() {
        assert_eq!(err("1.5"), "floats are not supported");
        assert_eq!(err("1e3"), "floats are not supported");
        assert_eq!(err(r#"{"a":0.0}"#), "floats are not supported");
    }

    #[test]
    fn rejects_malformed_numbers() {
        assert_eq!(err("-"), "expected digits in number");
        assert_eq!(err("01"), "leading zero in number");
        assert_eq!(err("-01"), "leading zero in number");
        assert_eq!(err("+1"), "unexpected character");
        assert_eq!(err("9223372036854775808"), "integer out of i64 range");
        assert_eq!(err("-9223372036854775809"), "integer out of i64 range");
        // Not a leading-zero false positive.
        assert_eq!(parse("0").unwrap(), Value::Int(0));
        assert_eq!(parse("-0").unwrap(), Value::Int(0));
    }

    #[test]
    fn rejects_duplicate_keys() {
        let e = parse(r#"{"name":"a","name":"b"}"#).unwrap_err();
        assert_eq!(e.msg, "duplicate key \"name\"");
        assert_eq!(e.offset, 12); // points at the second key
    }

    #[test]
    fn rejects_broken_structure() {
        assert_eq!(err(""), "unexpected end of input");
        assert_eq!(err("   "), "unexpected end of input");
        assert_eq!(err(r#"{"a":1,}"#), "expected object key");
        assert_eq!(err("[1,]"), "unexpected character");
        assert_eq!(err(r#"{"a" 1}"#), "expected ':'");
        assert_eq!(err("{a:1}"), "expected object key");
        assert_eq!(err(r#"{"a":1"#), "expected ',' or '}'");
        assert_eq!(err("[1"), "expected ',' or ']'");
        assert_eq!(err("{}{}"), "trailing content after JSON value");
        assert_eq!(err("1 2"), "trailing content after JSON value");
        assert_eq!(err("tru"), "invalid literal");
        assert_eq!(err("nulll"), "trailing content after JSON value");
        assert_eq!(err("'a'"), "unexpected character");
    }

    #[test]
    fn rejects_broken_strings() {
        assert_eq!(err(r#""unterminated"#), "unterminated string");
        assert_eq!(err(r#""bad \q escape""#), "invalid escape");
        assert_eq!(
            err("\"raw\nnewline\""),
            "unescaped control character in string"
        );
        assert_eq!(err("\"raw\ttab\""), "unescaped control character in string");
        assert_eq!(err(r#""\u12""#), "truncated \\u escape");
        assert_eq!(err(r#""\u12g4""#), "invalid hex digit in \\u escape");
        assert_eq!(err(r#""\u12"#), "truncated \\u escape");
        assert_eq!(err(r#""\uZZZZ""#), "invalid hex digit in \\u escape");
        assert_eq!(err(r#""\ud83d""#), "lone high surrogate in \\u escape");
        assert_eq!(err(r#""\ud83dA""#), "lone high surrogate in \\u escape");
        assert_eq!(
            err(r#""\ud83d\u0041""#),
            "invalid low surrogate in \\u escape"
        );
        assert_eq!(err(r#""\udc1f""#), "lone low surrogate in \\u escape");
        assert_eq!(err(r#""trailing\"#), "unterminated escape");
    }

    #[test]
    fn rejects_nesting_past_the_depth_limit() {
        let ok = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(parse(&ok).is_ok());
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 2), "]".repeat(MAX_DEPTH + 2));
        assert_eq!(parse(&deep).unwrap_err().msg, "nesting too deep");
    }

    #[test]
    fn error_offsets_point_at_the_problem() {
        let e = parse(r#"{"a":1,"b":1.5}"#).unwrap_err();
        assert_eq!(e.offset, 12);
        assert_eq!(e.to_string(), "floats are not supported (at byte 12)");
    }
}
