//! DNS messages (RFC 1035), enough to ask one question: **is this name
//! serving this TXT value yet?**
//!
//! This exists because "Cloudflare stored the record" and "the name
//! answers with it" are different facts, and DNS-01 only cares about
//! the second. The control-plane API can only report the first, so
//! checking propagation means asking DNS itself — and `std` has no
//! resolver, only name-to-address lookup, which cannot ask for TXT.
//!
//! What is here is a question builder and an answer reader, both pure:
//! bytes in, bytes out, no socket. The binary owns the UDP socket and
//! the choice of which servers to ask.
//!
//! **This is not a resolver.** There is no recursion, no cache, no
//! trust evaluation, and no signature checking. It asks a server that
//! is already known to be authoritative for the name and reads what
//! comes back. Nothing security-critical rests on the answer: a wrong
//! one only makes anago hand a challenge to the ACME server early or
//! late, and the ACME server does its own lookup, which is the one that
//! decides (§7).

use std::fmt;

/// `TXT` (RFC 1035 §3.2.2).
pub const TYPE_TXT: u16 = 16;

/// `IN` — the internet class.
pub const CLASS_IN: u16 = 1;

/// `OPT` — the pseudo-record EDNS(0) carries its options in (RFC 6891).
pub const TYPE_OPT: u16 = 41;

/// The UDP answer size asked for with EDNS(0).
///
/// Without it a server may send at most 512 bytes and sets the
/// truncation bit for anything larger — and an `_acme-challenge` name
/// legitimately holds several TXT values at once, so 512 bytes is a
/// size real answers reach. 1232 is the usual choice: it fits inside
/// the smallest MTU worth assuming on IPv6 (1280) with room for the
/// headers, so the datagram arrives whole rather than being fragmented
/// on the way.
pub const UDP_PAYLOAD: u16 = 1232;

/// No error.
pub const RCODE_OK: u8 = 0;

/// `NXDOMAIN` — the name does not exist. For a challenge record that
/// is an ordinary "not yet", not a failure.
pub const RCODE_NAME_ERROR: u8 = 3;

const HEADER_LEN: usize = 12;
const MAX_NAME: usize = 255;
const MAX_LABEL: usize = 63;

/// How many compression pointers one name may follow before the
/// message is called malformed. A pointer loop is the classic way to
/// make a parser spin forever; a name has at most 127 labels, so any
/// real message is far below this.
const MAX_JUMPS: usize = 32;

/// A TXT question, ready to put on the wire.
///
/// Recursion is **not** requested: the servers this asks are the ones
/// authoritative for the name, and asking them to recurse is both
/// pointless and, for most of them, refused.
///
/// `id` is the caller's to choose. It matches the answer to the
/// question and nothing more — this is not a defence against a forged
/// answer, and it is not trying to be. An attacker who could forge one
/// would gain the ability to make anago start validation a few seconds
/// early or wait a minute; the ACME server's own lookup is what decides
/// whether a certificate is issued.
///
/// The question carries an EDNS(0) `OPT` record asking for answers up
/// to [`UDP_PAYLOAD`] bytes. Without it the limit is 512, and a name
/// holding several TXT values — the state DNS-01 allows while a
/// wildcard and a plain order validate together — comes back truncated,
/// with the value that was being waited for quite possibly in the part
/// that did not fit.
pub fn txt_query(id: u16, name: &str) -> Result<Vec<u8>, DnsError> {
    let question = encode_name(name)?;
    let mut message = Vec::with_capacity(HEADER_LEN + question.len() + 15);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&[0, 0]); // flags: a query, no recursion
    message.extend_from_slice(&1u16.to_be_bytes()); // one question
    message.extend_from_slice(&[0, 0]); // no answers
    message.extend_from_slice(&[0, 0]); // no authority records
    message.extend_from_slice(&1u16.to_be_bytes()); // one additional: OPT
    message.extend_from_slice(&question);
    message.extend_from_slice(&TYPE_TXT.to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());
    // OPT (RFC 6891 §6.1.2): the root name, then the payload size where
    // a class would be, and a zero TTL — no extended rcode, no flags,
    // no options.
    message.push(0);
    message.extend_from_slice(&TYPE_OPT.to_be_bytes());
    message.extend_from_slice(&UDP_PAYLOAD.to_be_bytes());
    message.extend_from_slice(&0u32.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    Ok(message)
}

/// What a server said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// 0 is an answer, 3 is "no such name", anything else is a server
    /// that could not answer — see [`RCODE_OK`], [`RCODE_NAME_ERROR`].
    pub rcode: u8,
    /// The server had more to say than fit in a UDP datagram.
    ///
    /// What is in [`Reply::values`] is still true; what is **not** in
    /// them proves nothing, because the missing part is exactly what
    /// did not fit. A caller waiting for one value must not read a
    /// truncated answer without it as "not there".
    pub truncated: bool,
    /// TXT values at the name asked about, each already joined from the
    /// character-strings that make it up.
    pub values: Vec<String>,
}

impl Reply {
    /// Whether the server answered at all, as opposed to reporting that
    /// it could not. `NXDOMAIN` counts as an answer: "nothing is there"
    /// is a fact about the name, not a failure of the server.
    pub fn answered(&self) -> bool {
        self.rcode == RCODE_OK || self.rcode == RCODE_NAME_ERROR
    }

    pub fn holds(&self, value: &str) -> bool {
        self.values.iter().any(|held| held == value)
    }
}

/// Reads an answer to [`txt_query`].
///
/// `name` is the name that was asked about; records for anything else
/// are ignored rather than trusted, so a CNAME chain or an unrelated
/// record in the same message cannot be read as the answer.
pub fn read_txt(message: &[u8], id: u16, name: &str) -> Result<Reply, DnsError> {
    if message.len() < HEADER_LEN {
        return Err(DnsError::Malformed("shorter than a header"));
    }
    if u16::from_be_bytes([message[0], message[1]]) != id {
        return Err(DnsError::NotOurQuestion);
    }
    if message[2] & 0x80 == 0 {
        return Err(DnsError::Malformed("not marked as an answer"));
    }

    let truncated = message[2] & 0x02 != 0;
    let rcode = message[3] & 0x0f;
    let questions = u16::from_be_bytes([message[4], message[5]]);
    let answers = u16::from_be_bytes([message[6], message[7]]);

    let wanted = fold(name);
    let mut at = HEADER_LEN;
    for _ in 0..questions {
        at = skip_name(message, at)?;
        at = at
            .checked_add(4)
            .filter(|end| *end <= message.len())
            .ok_or(DnsError::Malformed("a question runs past the end"))?;
    }

    let mut values = Vec::new();
    for _ in 0..answers {
        let (owner, after) = read_name(message, at)?;
        // A record header is name + type + class + ttl + rdlength.
        let Some(rdata) = after.checked_add(10).filter(|end| *end <= message.len()) else {
            // A server that set TC may cut the last record short. What
            // arrived is still worth reading; what did not is simply
            // not there yet.
            return finish(truncated, rcode, values);
        };
        let kind = u16::from_be_bytes([message[after], message[after + 1]]);
        let class = u16::from_be_bytes([message[after + 2], message[after + 3]]);
        let length = u16::from_be_bytes([message[rdata - 2], message[rdata - 1]]) as usize;
        let Some(end) = rdata
            .checked_add(length)
            .filter(|end| *end <= message.len())
        else {
            return finish(truncated, rcode, values);
        };

        if kind == TYPE_TXT && class == CLASS_IN && fold(&owner) == wanted {
            values.push(read_character_strings(&message[rdata..end]));
        }
        at = end;
    }

    finish(truncated, rcode, values)
}

fn finish(truncated: bool, rcode: u8, values: Vec<String>) -> Result<Reply, DnsError> {
    Ok(Reply {
        rcode,
        truncated,
        values,
    })
}

/// TXT data is a sequence of length-prefixed strings, and a value
/// longer than 255 bytes is simply split across several of them. They
/// are joined back together here, which is what every DNS client does
/// and what an ACME server expects to be able to do.
fn read_character_strings(rdata: &[u8]) -> String {
    let mut value = String::new();
    let mut at = 0;
    while at < rdata.len() {
        let length = rdata[at] as usize;
        let start = at + 1;
        let end = (start + length).min(rdata.len());
        value.push_str(&String::from_utf8_lossy(&rdata[start..end]));
        at = end;
    }
    value
}

/// A name in wire form: each label length-prefixed, terminated by a
/// zero length.
fn encode_name(name: &str) -> Result<Vec<u8>, DnsError> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return Err(DnsError::BadName("empty"));
    }
    if !name.is_ascii() {
        // Punycode is the wire form; converting is not this module's
        // job and guessing at it would ask about the wrong name.
        return Err(DnsError::BadName("not ASCII — needs its xn-- form"));
    }
    let mut wire = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        if label.is_empty() {
            return Err(DnsError::BadName("an empty label"));
        }
        if label.len() > MAX_LABEL {
            return Err(DnsError::BadName("a label longer than 63 bytes"));
        }
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    if wire.len() > MAX_NAME {
        return Err(DnsError::BadName("longer than 255 bytes"));
    }
    Ok(wire)
}

/// Reads a name, following compression pointers, and reports where the
/// name ended **in the stream** — which is after the first pointer, not
/// wherever the pointer led.
fn read_name(message: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut at = start;
    let mut after = None;
    let mut jumps = 0;

    loop {
        let length = *message
            .get(at)
            .ok_or(DnsError::Malformed("a name runs past the end"))?;
        match length & 0xc0 {
            0 => {
                if length == 0 {
                    return Ok((name, after.unwrap_or(at + 1)));
                }
                let from = at + 1;
                let to = from + length as usize;
                let label = message
                    .get(from..to)
                    .ok_or(DnsError::Malformed("a label runs past the end"))?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(&String::from_utf8_lossy(label));
                at = to;
            }
            0xc0 => {
                let low = *message
                    .get(at + 1)
                    .ok_or(DnsError::Malformed("a pointer runs past the end"))?;
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return Err(DnsError::Malformed("compression pointers in a loop"));
                }
                after.get_or_insert(at + 2);
                at = (((length & 0x3f) as usize) << 8) | low as usize;
            }
            _ => return Err(DnsError::Malformed("a label length that is not one")),
        }
    }
}

fn skip_name(message: &[u8], at: usize) -> Result<usize, DnsError> {
    read_name(message, at).map(|(_, after)| after)
}

/// Names compare without case, and without a trailing root dot.
fn fold(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Why a DNS message could not be built or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    BadName(&'static str),
    /// The answer's id is not the question's. Somebody else's packet,
    /// or a stale one from a previous question.
    NotOurQuestion,
    Malformed(&'static str),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::BadName(why) => {
                write!(f, "that is not a DNS name anago can ask about: {why}")
            }
            DnsError::NotOurQuestion => {
                f.write_str("the DNS answer does not belong to the question that was asked")
            }
            DnsError::Malformed(what) => write!(f, "the DNS answer could not be read: {what}"),
        }
    }
}

impl std::error::Error for DnsError {}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "_acme-challenge.net.example.com";
    const DIGEST: &str = "toxT9dGLhpBGCM3EhdcQoULLTuF-eqAaOJyBBnA_AbY";
    const ID: u16 = 0x4a3b;

    /// Assembles an answer to [`txt_query`], the way a server would:
    /// the question echoed back, then the answers, with the owner name
    /// written as a compression pointer to the question — which is what
    /// every real server does and the one thing a naive reader breaks
    /// on.
    fn answer(rcode: u8, truncated: bool, records: &[Vec<u8>]) -> Vec<u8> {
        let question = encode_name(NAME).unwrap();
        let mut message = Vec::new();
        message.extend_from_slice(&ID.to_be_bytes());
        message.push(0x80 | if truncated { 0x02 } else { 0 });
        message.push(rcode);
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&(records.len() as u16).to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes()); // the server's own OPT
        message.extend_from_slice(&question);
        message.extend_from_slice(&TYPE_TXT.to_be_bytes());
        message.extend_from_slice(&CLASS_IN.to_be_bytes());
        for record in records {
            message.extend_from_slice(record);
        }
        // An OPT sits in the additional section of every EDNS answer,
        // after the records that matter. Reading stops at the answer
        // count, so it is never mistaken for one of them.
        message.push(0);
        message.extend_from_slice(&TYPE_OPT.to_be_bytes());
        message.extend_from_slice(&UDP_PAYLOAD.to_be_bytes());
        message.extend_from_slice(&0u32.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        message
    }

    /// One record whose owner is a pointer at the question's name.
    fn record(kind: u16, rdata: &[u8]) -> Vec<u8> {
        let mut wire = vec![0xc0, HEADER_LEN as u8];
        wire.extend_from_slice(&kind.to_be_bytes());
        wire.extend_from_slice(&CLASS_IN.to_be_bytes());
        wire.extend_from_slice(&60u32.to_be_bytes());
        wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        wire.extend_from_slice(rdata);
        wire
    }

    /// The OPT record every EDNS answer ends with, in bytes — the tail
    /// a test has to cut through to reach the records before it.
    const OPT_LEN: usize = 11;

    fn txt(value: &str) -> Vec<u8> {
        let mut rdata = Vec::new();
        for chunk in value.as_bytes().chunks(255) {
            rdata.push(chunk.len() as u8);
            rdata.extend_from_slice(chunk);
        }
        record(TYPE_TXT, &rdata)
    }

    #[test]
    fn a_question_is_one_name_one_type_and_no_recursion() {
        let query = txt_query(ID, "_acme-challenge.example.com").unwrap();
        assert_eq!(&query[0..2], &ID.to_be_bytes());
        assert_eq!(&query[2..4], &[0, 0], "recursion is not asked for");
        assert_eq!(&query[4..6], &1u16.to_be_bytes(), "one question");
        assert_eq!(&query[6..10], &[0; 4], "no answers, no authority");
        assert_eq!(&query[10..12], &1u16.to_be_bytes(), "one additional: OPT");
        // Labels, length-prefixed, root-terminated, then type and class.
        assert_eq!(&query[12..13], &[15]);
        assert_eq!(&query[13..28], b"_acme-challenge");
    }

    #[test]
    fn the_question_asks_for_answers_bigger_than_512_bytes() {
        // Without EDNS(0) a server may send at most 512 bytes and sets
        // the truncation bit past that — and several TXT values at one
        // _acme-challenge name is a size real answers reach.
        let query = txt_query(ID, NAME).unwrap();
        let opt = &query[query.len() - 11..];
        assert_eq!(opt[0], 0, "the OPT record's name is the root");
        assert_eq!(&opt[1..3], &TYPE_OPT.to_be_bytes());
        assert_eq!(&opt[3..5], &UDP_PAYLOAD.to_be_bytes());
        assert_eq!(&opt[5..9], &[0; 4], "no extended rcode, no flags");
        assert_eq!(&opt[9..11], &[0, 0], "no options");
        const {
            assert!(
                UDP_PAYLOAD > 512,
                "512 is the limit EDNS(0) is here to lift"
            )
        };
    }

    #[test]
    fn an_opt_record_in_the_answer_is_not_read_as_an_answer() {
        // Every EDNS answer carries one in the additional section.
        // Reading stops at the answer count, so it never becomes a
        // value — a reader that walked to the end of the message would
        // turn it into a phantom record.
        let reply = read_txt(&answer(RCODE_OK, false, &[txt(DIGEST)]), ID, NAME).unwrap();
        assert_eq!(reply.values, [DIGEST]);
    }

    #[test]
    fn a_trailing_root_dot_asks_the_same_question() {
        assert_eq!(
            txt_query(ID, "example.com.").unwrap(),
            txt_query(ID, "example.com").unwrap()
        );
    }

    #[test]
    fn a_name_that_cannot_go_on_the_wire_is_refused() {
        for bad in ["", ".", "a..com", "맥북.example.com"] {
            assert!(
                matches!(txt_query(ID, bad), Err(DnsError::BadName(_))),
                "{bad}"
            );
        }
        let long_label = format!("{}.example.com", "a".repeat(64));
        assert!(matches!(
            txt_query(ID, &long_label),
            Err(DnsError::BadName(_))
        ));
        let long_name = format!("{}example.com", "label.".repeat(42));
        assert!(matches!(
            txt_query(ID, &long_name),
            Err(DnsError::BadName(_))
        ));
    }

    #[test]
    fn the_value_at_the_name_is_read_back() {
        let reply = read_txt(&answer(RCODE_OK, false, &[txt(DIGEST)]), ID, NAME).unwrap();
        assert_eq!(
            reply,
            Reply {
                rcode: RCODE_OK,
                truncated: false,
                values: vec![DIGEST.to_string()],
            }
        );
        assert!(reply.answered());
        assert!(reply.holds(DIGEST));
        assert!(!reply.holds("some-other-digest"));
    }

    #[test]
    fn several_values_at_one_name_all_come_back() {
        // The state DNS-01 explicitly allows: a wildcard order and a
        // plain one validating at the same time.
        let reply = read_txt(
            &answer(RCODE_OK, false, &[txt("someone-elses"), txt(DIGEST)]),
            ID,
            NAME,
        )
        .unwrap();
        assert_eq!(reply.values, ["someone-elses", DIGEST]);
        assert!(reply.holds(DIGEST));
    }

    #[test]
    fn a_value_split_across_character_strings_is_joined_up() {
        // Anything over 255 bytes arrives in pieces; a client that
        // reads only the first piece sees a value that never matches.
        let long = "x".repeat(300);
        let reply = read_txt(&answer(RCODE_OK, false, &[txt(&long)]), ID, NAME).unwrap();
        assert_eq!(reply.values, [long]);
    }

    #[test]
    fn a_name_that_does_not_exist_yet_is_an_answer_not_a_failure() {
        // The ordinary state a second after publishing.
        let reply = read_txt(&answer(RCODE_NAME_ERROR, false, &[]), ID, NAME).unwrap();
        assert_eq!(reply.rcode, RCODE_NAME_ERROR);
        assert!(reply.values.is_empty());
        assert!(reply.answered(), "the server answered: nothing is there");
    }

    #[test]
    fn a_server_that_could_not_answer_is_not_an_answer() {
        // SERVFAIL and REFUSED say nothing about the name, so the
        // caller must not read them as "the record is missing".
        for rcode in [2, 5] {
            let reply = read_txt(&answer(rcode, false, &[]), ID, NAME).unwrap();
            assert!(!reply.answered(), "rcode {rcode}");
        }
    }

    #[test]
    fn records_of_other_types_and_other_names_are_not_the_answer() {
        // A CNAME beside the TXT, and a TXT belonging to another name,
        // are both things a message can carry.
        let mut elsewhere = encode_name("other.example.com").unwrap();
        elsewhere.extend_from_slice(&TYPE_TXT.to_be_bytes());
        elsewhere.extend_from_slice(&CLASS_IN.to_be_bytes());
        elsewhere.extend_from_slice(&60u32.to_be_bytes());
        elsewhere.extend_from_slice(&(DIGEST.len() as u16 + 1).to_be_bytes());
        elsewhere.push(DIGEST.len() as u8);
        elsewhere.extend_from_slice(DIGEST.as_bytes());

        let message = answer(RCODE_OK, false, &[record(5, &[0]), elsewhere, txt("ours")]);
        let reply = read_txt(&message, ID, NAME).unwrap();
        assert_eq!(reply.values, ["ours"]);
    }

    #[test]
    fn an_answer_to_someone_elses_question_is_refused() {
        let message = answer(RCODE_OK, false, &[txt(DIGEST)]);
        assert_eq!(
            read_txt(&message, ID.wrapping_add(1), NAME),
            Err(DnsError::NotOurQuestion)
        );
    }

    #[test]
    fn a_query_echoed_back_as_a_query_is_not_an_answer() {
        let message = txt_query(ID, NAME).unwrap();
        assert!(matches!(
            read_txt(&message, ID, NAME),
            Err(DnsError::Malformed(_))
        ));
    }

    #[test]
    fn a_truncated_answer_says_so_because_what_is_missing_proves_nothing() {
        // The values that arrived are true; the absence of one is not.
        // A caller that read this as "the record is not there" would
        // fail a challenge that had already propagated.
        let reply = read_txt(&answer(RCODE_OK, true, &[txt("someone-elses")]), ID, NAME).unwrap();
        assert!(reply.truncated);
        assert!(reply.answered());
        assert!(!reply.holds(DIGEST));
    }

    #[test]
    fn a_truncated_message_gives_up_what_it_has_rather_than_erroring() {
        // A server that sets TC may cut the last record short. What
        // arrived is still an answer; what did not is not there yet.
        let mut message = answer(RCODE_OK, true, &[txt(DIGEST), txt("cut-in-half")]);
        message.truncate(message.len() - OPT_LEN - 7);
        let reply = read_txt(&message, ID, NAME).unwrap();
        assert!(reply.truncated);
        assert_eq!(reply.values, [DIGEST]);
    }

    #[test]
    fn a_message_that_stops_mid_record_is_malformed_when_nothing_says_it_was_cut() {
        let mut message = answer(RCODE_OK, false, &[txt(DIGEST)]);
        message.truncate(message.len() - OPT_LEN - 7);
        // Not marked truncated, so the reader keeps what it parsed and
        // does not invent the rest.
        let reply = read_txt(&message, ID, NAME).unwrap();
        assert!(reply.values.is_empty());
    }

    #[test]
    fn a_pointer_loop_ends_rather_than_spinning() {
        // The classic way to hang a DNS parser: a name that points at
        // itself.
        let mut message = answer(RCODE_OK, false, &[]);
        message.truncate(message.len() - OPT_LEN);
        message[6..8].copy_from_slice(&1u16.to_be_bytes());
        message[10..12].copy_from_slice(&0u16.to_be_bytes());
        let loop_at = message.len();
        message.push(0xc0);
        message.push(loop_at as u8);
        assert_eq!(
            read_txt(&message, ID, NAME),
            Err(DnsError::Malformed("compression pointers in a loop"))
        );
    }

    #[test]
    fn a_header_that_is_not_even_a_header_is_refused() {
        assert!(matches!(
            read_txt(&[0; 4], ID, NAME),
            Err(DnsError::Malformed(_))
        ));
    }

    #[test]
    fn the_name_is_matched_without_case() {
        let mut message = answer(RCODE_OK, false, &[txt(DIGEST)]);
        // Servers may echo the question in the case it was asked, or
        // in the case they store — both are the same name.
        let upper = NAME.to_ascii_uppercase();
        message[HEADER_LEN..HEADER_LEN + encode_name(NAME).unwrap().len()]
            .copy_from_slice(&encode_name(&upper).unwrap());
        assert!(read_txt(&message, ID, NAME).unwrap().holds(DIGEST));
    }

    #[test]
    fn errors_say_what_could_not_be_read() {
        assert!(DnsError::BadName("empty").to_string().contains("empty"));
        assert!(DnsError::NotOurQuestion
            .to_string()
            .contains("does not belong"));
        assert!(DnsError::Malformed("a label runs past the end")
            .to_string()
            .contains("past the end"));
    }
}
