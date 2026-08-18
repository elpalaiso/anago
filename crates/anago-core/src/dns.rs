//! Deciding what to do with the hub's A record (DESIGN.md §9.1, §13).
//!
//! The Cloudflare calls live in the binary; the judgement lives here, so
//! "create, edit, leave alone, or stop and tell someone" is fixed by
//! unit tests rather than by whatever a zone happened to contain the day
//! it was tried.
//!
//! Two rules shape everything below, and both are about **not silently
//! changing something a person owns**:
//!
//! - A proxied record is refused, never un-proxied. The orange cloud
//!   may be carrying traffic that has nothing to do with anago, and
//!   turning it off would reroute it (§13).
//! - Several A records at one name are refused, never merged. The name
//!   would round-robin, so half of the answers point away from the hub
//!   — updating one of them keeps a broken network alive while the
//!   output reports success (§9.1).

use std::fmt;
use std::net::Ipv4Addr;

/// One DNS record as Cloudflare lists it, reduced to the fields the
/// judgement uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub id: String,
    /// Record type as the API spells it — `"A"`, `"CNAME"`, `"TXT"`.
    /// Compared case-insensitively; the API is not consistent about it.
    pub kind: String,
    /// The record's value. For an A record, an IPv4 address in text.
    pub content: String,
    /// Whether the orange cloud is on.
    pub proxied: bool,
}

impl Record {
    /// An unproxied A record — the shape anago creates.
    pub fn a(id: impl Into<String>, content: impl Into<String>) -> Record {
        Record {
            id: id.into(),
            kind: "A".to_string(),
            content: content.into(),
            proxied: false,
        }
    }

    pub fn is_a(&self) -> bool {
        self.kind.eq_ignore_ascii_case("A")
    }

    fn is_cname(&self) -> bool {
        self.kind.eq_ignore_ascii_case("CNAME")
    }

    fn points_at(&self, ip: Ipv4Addr) -> bool {
        // An unparsable value is simply not the address we want; it
        // gets corrected like any other wrong value.
        self.content.trim().parse::<Ipv4Addr>() == Ok(ip)
    }
}

/// What to do with the hub's A record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upsert {
    /// Nothing is there. Create it — unproxied (§13).
    Create,
    /// Point an existing record at the hub. `adopted` is true when it
    /// was not the record anago made: a person created it by hand
    /// following M0's instructions, and this run is taking it over.
    /// Worth saying out loud, since anago is about to edit something it
    /// did not write.
    Update { record_id: String, adopted: bool },
    /// Already correct. Still carries the id, because a run that found
    /// the record without a cache hit should still remember it.
    Unchanged { record_id: String },
    /// Stop and tell the person.
    Refuse(Refusal),
}

impl Upsert {
    /// The id the cache should hold after acting on this decision, when
    /// it is already known. [`Upsert::Create`] returns `None` — the id
    /// does not exist until Cloudflare answers.
    ///
    /// A refusal keeps whatever the cache held: it is a state for a
    /// person to fix, not one to forget (§9.1).
    pub fn record_id(&self) -> Option<&str> {
        match self {
            Upsert::Update { record_id, .. } | Upsert::Unchanged { record_id } => Some(record_id),
            Upsert::Create | Upsert::Refuse(_) => None,
        }
    }

    pub fn refusal(&self) -> Option<&Refusal> {
        match self {
            Upsert::Refuse(refusal) => Some(refusal),
            _ => None,
        }
    }
}

/// Why anago will not touch this name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The record is behind the orange cloud. `51820/udp` is not
    /// forwarded through it, so the tunnel would fail while the
    /// certificate still issued — §13's worst shape of failure.
    Proxied { record_id: String },
    /// A CNAME sits at this name. DNS does not let a CNAME share a name
    /// with anything else, so there is no A record to add here.
    Cname { record_id: String },
    /// Several A records answer to this name. `ours` names the cached
    /// one when the cache still points at a record that is there.
    Ambiguous { count: usize, ours: Option<String> },
    /// The cached id is at this name but is no longer an A record.
    /// Refused rather than re-created: something else now owns that id.
    CachedNotAnARecord { record_id: String, kind: String },
}

/// Decides what the hub's A record needs, given every record Cloudflare
/// lists at that name, the address it should point at, and the id anago
/// last recorded (§9.1).
///
/// `records` is the whole list for the name, not only the A records:
/// a CNAME in the way and a cached id that changed type are both things
/// worth reporting rather than tripping over at the API.
///
/// A cached id that is simply absent needs no special outcome: the id
/// is dropped and the same rules run again over what is actually there.
/// That is all invalidation means here — **not** "create a new one".
/// A stale cache beside an existing A record adopts that record, because
/// creating a second one is how the round-robin above happens (§9.1).
pub fn decide(records: &[Record], desired: Ipv4Addr, cached_id: Option<&str>) -> Upsert {
    // The cache first, so a changed record type is reported as that
    // rather than as an absence.
    if let Some(cached) = cached_id.and_then(|id| records.iter().find(|r| r.id == id)) {
        if !cached.is_a() {
            return Upsert::Refuse(Refusal::CachedNotAnARecord {
                record_id: cached.id.clone(),
                kind: cached.kind.clone(),
            });
        }
    }

    if let Some(cname) = records.iter().find(|r| r.is_cname()) {
        return Upsert::Refuse(Refusal::Cname {
            record_id: cname.id.clone(),
        });
    }

    let a_records: Vec<&Record> = records.iter().filter(|r| r.is_a()).collect();
    let ours = match a_records.len() {
        0 => return Upsert::Create,
        1 => a_records[0],
        count => {
            return Upsert::Refuse(Refusal::Ambiguous {
                count,
                ours: cached_id
                    .filter(|id| a_records.iter().any(|r| r.id == *id))
                    .map(str::to_string),
            })
        }
    };

    if ours.proxied {
        return Upsert::Refuse(Refusal::Proxied {
            record_id: ours.id.clone(),
        });
    }

    if ours.points_at(desired) {
        return Upsert::Unchanged {
            record_id: ours.id.clone(),
        };
    }

    Upsert::Update {
        record_id: ours.id.clone(),
        adopted: cached_id != Some(ours.id.as_str()),
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Proxied { record_id } => write!(
                f,
                "the A record ({record_id}) is proxied; anago will not turn that off. \
                 WireGuard's UDP port is not forwarded through the proxy, so set the \
                 record to DNS only (grey cloud) and run this again"
            ),
            Refusal::Cname { record_id } => write!(
                f,
                "a CNAME ({record_id}) already answers to this name, and DNS does not \
                 allow an A record beside it. Remove the CNAME, or point anago at a \
                 name of its own"
            ),
            Refusal::Ambiguous { count, ours } => {
                write!(
                    f,
                    "{count} A records answer to this name, so it resolves to a \
                        different address every other lookup and the hub is reachable \
                        only half the time"
                )?;
                match ours {
                    Some(id) => write!(f, ". anago created {id}; remove the others"),
                    None => f.write_str(". Leave exactly the one that points at this server"),
                }
            }
            Refusal::CachedNotAnARecord { record_id, kind } => write!(
                f,
                "the record anago recorded ({record_id}) is now a {kind} record, not an A \
                 record. Something else owns it; sort that out rather than letting anago \
                 overwrite it"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

#[cfg(test)]
mod tests {
    use super::*;

    const HUB: &str = "203.0.113.10";
    const OTHER: &str = "198.51.100.7";

    fn hub_ip() -> Ipv4Addr {
        HUB.parse().unwrap()
    }

    fn proxied(id: &str, content: &str) -> Record {
        Record {
            proxied: true,
            ..Record::a(id, content)
        }
    }

    fn of_kind(id: &str, kind: &str, content: &str) -> Record {
        Record {
            id: id.to_string(),
            kind: kind.to_string(),
            content: content.to_string(),
            proxied: false,
        }
    }

    #[test]
    fn an_empty_name_is_created() {
        assert_eq!(decide(&[], hub_ip(), None), Upsert::Create);
        // A cache pointing at a record that is gone means the person
        // deleted it: create, and the caller records the new id.
        assert_eq!(decide(&[], hub_ip(), Some("stale")), Upsert::Create);
    }

    #[test]
    fn other_record_types_at_the_name_are_ignored() {
        // TXT (an ACME challenge, even) and MX coexist with an A record
        // perfectly well; only a CNAME cannot.
        let records = [
            of_kind("t1", "TXT", "v=spf1 -all"),
            of_kind("m1", "MX", "10 mail.example.com"),
        ];
        assert_eq!(decide(&records, hub_ip(), None), Upsert::Create);
    }

    #[test]
    fn a_correct_record_is_left_alone() {
        let records = [Record::a("r1", HUB)];
        assert_eq!(
            decide(&records, hub_ip(), Some("r1")),
            Upsert::Unchanged {
                record_id: "r1".to_string()
            }
        );
        // Without a cache the answer is the same, and it still carries
        // the id so the caller can start remembering it.
        assert_eq!(
            decide(&records, hub_ip(), None).record_id(),
            Some("r1"),
            "an uncached but correct record still names itself"
        );
    }

    #[test]
    fn whitespace_around_the_address_is_not_a_difference() {
        let records = [Record::a("r1", format!(" {HUB} "))];
        assert!(matches!(
            decide(&records, hub_ip(), Some("r1")),
            Upsert::Unchanged { .. }
        ));
    }

    #[test]
    fn our_own_record_pointing_elsewhere_is_updated() {
        let records = [Record::a("r1", OTHER)];
        assert_eq!(
            decide(&records, hub_ip(), Some("r1")),
            Upsert::Update {
                record_id: "r1".to_string(),
                adopted: false,
            }
        );
    }

    #[test]
    fn a_hand_made_record_is_adopted_and_says_so() {
        // The M0 → M1 path: the person added the record by hand
        // following init's instructions, and anago now takes it over
        // rather than creating a second one beside it.
        let records = [Record::a("r1", OTHER)];
        assert_eq!(
            decide(&records, hub_ip(), None),
            Upsert::Update {
                record_id: "r1".to_string(),
                adopted: true,
            }
        );
        // A cache that points somewhere else entirely is no better than
        // none: this record is still not the one anago made.
        assert_eq!(
            decide(&records, hub_ip(), Some("gone")),
            Upsert::Update {
                record_id: "r1".to_string(),
                adopted: true,
            }
        );
    }

    #[test]
    fn a_stale_cache_never_creates_a_second_record() {
        // Invalidation drops the id; it does not decide what happens
        // next. With a record already at the name, creating another is
        // exactly how a name ends up round-robining (§9.1).
        let correct = [Record::a("r1", HUB)];
        assert_eq!(
            decide(&correct, hub_ip(), Some("gone")),
            Upsert::Unchanged {
                record_id: "r1".to_string()
            }
        );
        let wrong = [Record::a("r1", OTHER)];
        assert_eq!(
            decide(&wrong, hub_ip(), Some("gone")),
            Upsert::Update {
                record_id: "r1".to_string(),
                adopted: true,
            }
        );
        // `Create` is reached only when the name really is empty.
        assert_eq!(decide(&[], hub_ip(), Some("gone")), Upsert::Create);
    }

    #[test]
    fn an_unparsable_address_is_treated_as_wrong_not_as_equal() {
        let records = [Record::a("r1", "not-an-address")];
        assert!(matches!(
            decide(&records, hub_ip(), Some("r1")),
            Upsert::Update { .. }
        ));
    }

    #[test]
    fn a_proxied_record_is_refused_rather_than_un_proxied() {
        // §13: the certificate would still issue and the tunnel would
        // still be dead, so this must stop before anything reports
        // success.
        let records = [proxied("r1", HUB)];
        assert_eq!(
            decide(&records, hub_ip(), Some("r1")),
            Upsert::Refuse(Refusal::Proxied {
                record_id: "r1".to_string()
            })
        );
        // Even when the address is wrong as well — the proxy is the
        // thing a person has to decide about.
        let records = [proxied("r1", OTHER)];
        assert!(matches!(
            decide(&records, hub_ip(), None),
            Upsert::Refuse(Refusal::Proxied { .. })
        ));
    }

    #[test]
    fn a_cname_in_the_way_is_refused() {
        let records = [of_kind("c1", "CNAME", "example.pages.dev")];
        assert_eq!(
            decide(&records, hub_ip(), None),
            Upsert::Refuse(Refusal::Cname {
                record_id: "c1".to_string()
            })
        );
    }

    #[test]
    fn several_a_records_are_refused_not_merged() {
        // Updating one of these would leave the name round-robining and
        // report success (§9.1).
        let records = [Record::a("r1", HUB), Record::a("r2", OTHER)];
        assert_eq!(
            decide(&records, hub_ip(), None),
            Upsert::Refuse(Refusal::Ambiguous {
                count: 2,
                ours: None
            })
        );
    }

    #[test]
    fn the_cache_makes_an_ambiguous_refusal_specific() {
        let records = [Record::a("r1", HUB), Record::a("r2", OTHER)];
        assert_eq!(
            decide(&records, hub_ip(), Some("r1")),
            Upsert::Refuse(Refusal::Ambiguous {
                count: 2,
                ours: Some("r1".to_string())
            })
        );
        // A cache pointing at a record that is no longer here cannot
        // name ours, and must not name one at random.
        assert_eq!(
            decide(&records, hub_ip(), Some("gone")),
            Upsert::Refuse(Refusal::Ambiguous {
                count: 2,
                ours: None
            })
        );
    }

    #[test]
    fn a_cached_id_that_changed_type_is_refused() {
        let records = [of_kind("r1", "TXT", "hello"), Record::a("r2", HUB)];
        assert_eq!(
            decide(&records, hub_ip(), Some("r1")),
            Upsert::Refuse(Refusal::CachedNotAnARecord {
                record_id: "r1".to_string(),
                kind: "TXT".to_string(),
            })
        );
    }

    #[test]
    fn record_types_are_matched_case_insensitively() {
        // Cloudflare is not consistent about the case it echoes.
        let records = [of_kind("r1", "a", HUB)];
        assert!(matches!(
            decide(&records, hub_ip(), None),
            Upsert::Unchanged { .. }
        ));
        let records = [of_kind("c1", "cname", "elsewhere.example.com")];
        assert!(matches!(
            decide(&records, hub_ip(), None),
            Upsert::Refuse(Refusal::Cname { .. })
        ));
    }

    #[test]
    fn a_refusal_never_hands_back_an_id_to_cache() {
        // §9.1: a refusal keeps whatever the cache held. It is a state
        // for a person to fix, not one to forget.
        let records = [proxied("r1", HUB)];
        let decision = decide(&records, hub_ip(), Some("r1"));
        assert_eq!(decision.record_id(), None);
        assert!(decision.refusal().is_some());
    }

    #[test]
    fn refusals_say_what_to_do_about_them() {
        let proxied = Refusal::Proxied {
            record_id: "r1".to_string(),
        }
        .to_string();
        assert!(proxied.contains("DNS only"), "{proxied}");

        let ours = Refusal::Ambiguous {
            count: 3,
            ours: Some("r1".to_string()),
        }
        .to_string();
        assert!(ours.contains("3 A records"), "{ours}");
        assert!(ours.contains("remove the others"), "{ours}");

        let unknown = Refusal::Ambiguous {
            count: 2,
            ours: None,
        }
        .to_string();
        assert!(!unknown.contains("anago created"), "{unknown}");

        let cname = Refusal::Cname {
            record_id: "c1".to_string(),
        }
        .to_string();
        assert!(cname.contains("CNAME"), "{cname}");

        let changed = Refusal::CachedNotAnARecord {
            record_id: "r1".to_string(),
            kind: "TXT".to_string(),
        }
        .to_string();
        assert!(changed.contains("TXT"), "{changed}");
    }
}
