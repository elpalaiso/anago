//! What `anago sync` should do about what the hub just said
//! (DESIGN.md §6.3).
//!
//! The call, the wg commands and the file writing are the binary's; the
//! judgement is here, because the interesting part of sync is how
//! rarely it does anything. In hub-and-spoke a device's config is one
//! `AllowedIPs = <subnet>` line, so **another device joining changes
//! nothing here** — "pull the peer list and update the config" ends in
//! "nothing to update" almost every time, and that is the correct
//! ending, not a wasted run.
//!
//! What is worth a run is the rest: noticing that this device was
//! removed, telling the hub it is alive (any authenticated call does
//! that), and checking that the local config still matches the hub.
//! The last one needs something to compare against, which is why the
//! peers response carries the hub's own values (§6.3). An M0 hub sends
//! none, and then the comparison is **skipped, not failed** — reading
//! absence as difference would rewrite the config every five minutes.
//!
//! Nothing here is destructive. Every outcome that means "this device
//! no longer fits" stops and hands the person a cleanup, because an
//! unattended job that runs every five minutes must not take a tunnel
//! down on its own.

use std::fmt;
use std::net::Ipv4Addr;

use crate::name::DeviceName;
use crate::subnet::Subnet;

/// What this device believes, as `device.json` records it (§9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Local {
    pub name: DeviceName,
    pub address: Ipv4Addr,
    pub subnet: Subnet,
    pub server_public_key: String,
    /// `host:port` the device dials, e.g. `net.example.com:51820`.
    pub server_endpoint: String,
    pub server_address: Ipv4Addr,
}

/// What the hub says about itself, from `GET /api/v1/peers` (§6.3).
///
/// The same four values `join` handed out, which is why they need no
/// new meaning: this is the hub repeating itself so the device can
/// check its own copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reported {
    pub subnet: Subnet,
    pub server_public_key: String,
    pub server_endpoint: String,
    pub server_address: Ipv4Addr,
}

/// One device on the hub's roster, reduced to what identifies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub name: DeviceName,
    pub address: Ipv4Addr,
}

/// What to do after a successful `GET /api/v1/peers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sync {
    /// Everything matches. The common ending.
    Unchanged,
    /// The roster is fine, but this hub reported nothing about itself,
    /// so there was nothing to compare the local config against — an M0
    /// hub. Not an error: the device still works (§6.3).
    Unverifiable,
    /// Rewrite the wg config, apply it, then record the new values.
    /// That order matters: committing `device.json` before the apply
    /// succeeds would make the next run believe it already matched
    /// (§6.3).
    Rewrite(Changes),
    /// Stop. This device no longer fits the hub, and a person has to
    /// decide what to do about it.
    Detached(Detachment),
}

/// Which of the hub's values moved. Kept as flags rather than a bool so
/// the run can say what it is about to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Changes {
    pub server_public_key: bool,
    pub server_endpoint: bool,
    pub server_address: bool,
}

impl Changes {
    pub fn any(self) -> bool {
        self.server_public_key || self.server_endpoint || self.server_address
    }
}

/// Why this device no longer fits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detachment {
    /// The hub answered 401: the token is dead, so the device was
    /// removed with `anago rm` (§7.1).
    ///
    /// Built by the caller from the HTTP status rather than by
    /// [`decide`], so that every ending a person can be told about is
    /// spelled out in one place.
    Unauthorized,
    /// The roster does not list this name at all.
    Removed,
    /// The name is listed at a different address than this device
    /// holds. Not repaired here: an address that did not come from a
    /// join is a hub state anago does not understand, and re-joining is
    /// cheap and certain (§6.3).
    Reassigned { theirs: Ipv4Addr },
    /// The hub is serving a different network than the one this device
    /// joined — it was rebuilt.
    SubnetChanged { theirs: Subnet },
}

/// Compares what the device believes against what the hub just said.
///
/// `reported` is `None` when the hub did not describe itself (an M0
/// hub). `roster` is the peer list as returned, this device included.
///
/// Order is deliberate. The subnet is checked first because a rebuilt
/// hub also renumbers, and "this is a different network" is a more
/// useful thing to be told than "your address moved".
pub fn decide(local: &Local, reported: Option<&Reported>, roster: &[Member]) -> Sync {
    if let Some(reported) = reported {
        if reported.subnet != local.subnet {
            return Sync::Detached(Detachment::SubnetChanged {
                theirs: reported.subnet,
            });
        }
    }

    match roster.iter().find(|member| member.name == local.name) {
        None => return Sync::Detached(Detachment::Removed),
        Some(member) if member.address != local.address => {
            return Sync::Detached(Detachment::Reassigned {
                theirs: member.address,
            })
        }
        Some(_) => {}
    }

    // Everything past here needs something to compare against.
    let Some(reported) = reported else {
        return Sync::Unverifiable;
    };

    let changes = Changes {
        server_public_key: reported.server_public_key != local.server_public_key,
        server_endpoint: reported.server_endpoint != local.server_endpoint,
        server_address: reported.server_address != local.server_address,
    };

    if changes.any() {
        Sync::Rewrite(changes)
    } else {
        Sync::Unchanged
    }
}

impl fmt::Display for Changes {
    /// Names the fields that moved, for the one line a run prints.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (moved, label) in [
            (self.server_public_key, "server public key"),
            (self.server_endpoint, "server endpoint"),
            (self.server_address, "server address"),
        ] {
            if !moved {
                continue;
            }
            if !first {
                f.write_str(", ")?;
            }
            f.write_str(label)?;
            first = false;
        }
        if first {
            f.write_str("nothing")?;
        }
        Ok(())
    }
}

impl fmt::Display for Detachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Detachment::Unauthorized => f.write_str(
                "the hub rejected this device's token: it was removed with `anago rm`. \
                 Bring the tunnel down, delete the device file and the wg config, then \
                 join again with a fresh code",
            ),
            Detachment::Removed => f.write_str(
                "the hub no longer lists this device. Bring the tunnel down, delete the \
                 device file and the wg config, then join again with a fresh code",
            ),
            Detachment::Reassigned { theirs } => write!(
                f,
                "the hub lists this device at {theirs}, which is not the address it was \
                 given. anago will not move it on its own — join again to get an address \
                 the hub agrees with"
            ),
            Detachment::SubnetChanged { theirs } => write!(
                f,
                "the hub is serving {theirs}, a different network than this device joined. \
                 The hub was rebuilt; join it again"
            ),
        }
    }
}

impl std::error::Error for Detachment {}

#[cfg(test)]
mod tests {
    use super::*;

    const HUB_KEY: &str = "aHViIHB1YmxpYyBrZXk=";
    const ENDPOINT: &str = "net.example.com:51820";

    fn name(text: &str) -> DeviceName {
        DeviceName::parse(text).unwrap()
    }

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    fn subnet() -> Subnet {
        Subnet::parse("10.100.0.0/24").unwrap()
    }

    fn local() -> Local {
        Local {
            name: name("macbook"),
            address: ip("10.100.0.2"),
            subnet: subnet(),
            server_public_key: HUB_KEY.to_string(),
            server_endpoint: ENDPOINT.to_string(),
            server_address: ip("10.100.0.1"),
        }
    }

    fn reported() -> Reported {
        Reported {
            subnet: subnet(),
            server_public_key: HUB_KEY.to_string(),
            server_endpoint: ENDPOINT.to_string(),
            server_address: ip("10.100.0.1"),
        }
    }

    fn member(text: &str, address: &str) -> Member {
        Member {
            name: name(text),
            address: ip(address),
        }
    }

    fn roster() -> Vec<Member> {
        vec![member("macbook", "10.100.0.2")]
    }

    #[test]
    fn a_matching_hub_changes_nothing() {
        assert_eq!(
            decide(&local(), Some(&reported()), &roster()),
            Sync::Unchanged
        );
    }

    #[test]
    fn another_device_joining_changes_nothing() {
        // The property the whole design rests on (§6.3): the client
        // config is `AllowedIPs = <subnet>`, so peers come and go
        // without it. If this ever fails, sync starts rewriting configs
        // every time anyone joins.
        let mut roster = roster();
        roster.push(member("맥북", "10.100.0.3"));
        roster.push(member("phone", "10.100.0.4"));
        assert_eq!(
            decide(&local(), Some(&reported()), &roster),
            Sync::Unchanged
        );
    }

    #[test]
    fn another_device_leaving_changes_nothing() {
        let roster = vec![
            member("macbook", "10.100.0.2"),
            member("desktop", "10.100.0.3"),
        ];
        assert_eq!(
            decide(&local(), Some(&reported()), &roster),
            Sync::Unchanged
        );
        // And with the other one gone again.
        assert_eq!(
            decide(&local(), Some(&reported()), &roster[..1]),
            Sync::Unchanged
        );
    }

    #[test]
    fn the_order_of_the_roster_does_not_matter() {
        let roster = vec![
            member("phone", "10.100.0.9"),
            member("macbook", "10.100.0.2"),
        ];
        assert_eq!(
            decide(&local(), Some(&reported()), &roster),
            Sync::Unchanged
        );
    }

    #[test]
    fn a_missing_name_means_this_device_was_removed() {
        let roster = vec![member("desktop", "10.100.0.3")];
        assert_eq!(
            decide(&local(), Some(&reported()), &roster),
            Sync::Detached(Detachment::Removed)
        );
        assert_eq!(
            decide(&local(), Some(&reported()), &[]),
            Sync::Detached(Detachment::Removed)
        );
    }

    #[test]
    fn a_different_address_under_our_name_is_not_repaired_here() {
        let roster = vec![member("macbook", "10.100.0.7")];
        assert_eq!(
            decide(&local(), Some(&reported()), &roster),
            Sync::Detached(Detachment::Reassigned {
                theirs: ip("10.100.0.7")
            })
        );
    }

    #[test]
    fn a_different_subnet_is_reported_before_the_address_is() {
        // A rebuilt hub renumbers too, so checking the roster first
        // would report "your address moved" for what is really "this is
        // a different network".
        let mut reported = reported();
        reported.subnet = Subnet::parse("10.200.0.0/24").unwrap();
        reported.server_address = ip("10.200.0.1");
        let roster = vec![member("macbook", "10.200.0.2")];
        assert_eq!(
            decide(&local(), Some(&reported), &roster),
            Sync::Detached(Detachment::SubnetChanged {
                theirs: Subnet::parse("10.200.0.0/24").unwrap()
            })
        );
    }

    #[test]
    fn a_moved_hub_key_calls_for_a_rewrite() {
        let mut reported = reported();
        reported.server_public_key = "bmV3IGh1YiBrZXk=".to_string();
        assert_eq!(
            decide(&local(), Some(&reported), &roster()),
            Sync::Rewrite(Changes {
                server_public_key: true,
                ..Changes::default()
            })
        );
    }

    #[test]
    fn a_moved_endpoint_calls_for_a_rewrite() {
        let mut reported = reported();
        reported.server_endpoint = "net.example.com:51821".to_string();
        assert_eq!(
            decide(&local(), Some(&reported), &roster()),
            Sync::Rewrite(Changes {
                server_endpoint: true,
                ..Changes::default()
            })
        );
    }

    #[test]
    fn every_moved_field_is_reported_together() {
        let reported = Reported {
            subnet: subnet(),
            server_public_key: "bmV3IGh1YiBrZXk=".to_string(),
            server_endpoint: "elsewhere.example.com:51820".to_string(),
            server_address: ip("10.100.0.254"),
        };
        let decision = decide(&local(), Some(&reported), &roster());
        assert_eq!(
            decision,
            Sync::Rewrite(Changes {
                server_public_key: true,
                server_endpoint: true,
                server_address: true,
            })
        );
        let Sync::Rewrite(changes) = decision else {
            unreachable!()
        };
        assert_eq!(
            changes.to_string(),
            "server public key, server endpoint, server address"
        );
    }

    #[test]
    fn an_m0_hub_reports_nothing_and_that_is_not_a_difference() {
        // Reading absence as difference would rewrite the config every
        // five minutes, forever (§6.3).
        assert_eq!(decide(&local(), None, &roster()), Sync::Unverifiable);
    }

    #[test]
    fn an_m0_hub_can_still_say_this_device_is_gone() {
        // The roster check needs nothing from the hub block.
        assert_eq!(
            decide(&local(), None, &[]),
            Sync::Detached(Detachment::Removed)
        );
        let roster = vec![member("macbook", "10.100.0.7")];
        assert_eq!(
            decide(&local(), None, &roster),
            Sync::Detached(Detachment::Reassigned {
                theirs: ip("10.100.0.7")
            })
        );
    }

    #[test]
    fn names_are_compared_in_canonical_form() {
        // `DeviceName` lower-cases on parse (§8.1), so a hub that echoes
        // a differently-cased name is still this device.
        let roster = vec![member("MacBook", "10.100.0.2")];
        assert_eq!(
            decide(&local(), Some(&reported()), &roster),
            Sync::Unchanged
        );
    }

    #[test]
    fn changes_describe_themselves_for_the_one_line_a_run_prints() {
        assert_eq!(Changes::default().to_string(), "nothing");
        assert!(!Changes::default().any());
        assert_eq!(
            Changes {
                server_endpoint: true,
                ..Changes::default()
            }
            .to_string(),
            "server endpoint"
        );
    }

    #[test]
    fn every_detachment_tells_the_person_what_to_do() {
        for detachment in [
            Detachment::Unauthorized,
            Detachment::Removed,
            Detachment::Reassigned {
                theirs: ip("10.100.0.7"),
            },
            Detachment::SubnetChanged { theirs: subnet() },
        ] {
            let message = detachment.to_string();
            assert!(message.contains("join"), "{message}");
        }
    }
}
