//! Bringing the tunnel up after a join (DESIGN.md §6.2 step 3).
//!
//! Two commands and a question: `wg-quick up`, then a ping to the hub's
//! private address to see whether the tunnel actually carries traffic.
//! Both are delegated — anago does not touch netlink or ICMP itself.
//!
//! The interesting part is what to say when it does not work, and that
//! is a pure function of which step failed.

use std::fmt;
use std::net::Ipv4Addr;
use std::path::Path;

use crate::wg::{self, Cmd, Platform, WgError};

/// How long to wait for the hub to answer one ping, in seconds. Long
/// enough for a slow first handshake, short enough that a broken setup
/// does not feel like a hang.
pub const PING_TIMEOUT_SECS: u32 = 5;

/// `ping -c 1` with the platform's spelling of a timeout.
///
/// The flag differs and the difference matters: `-W` on Linux is a
/// per-reply timeout in seconds, while on macOS `-W` is milliseconds
/// and `-t` is the deadline.
pub fn ping_command(platform: Platform, address: Ipv4Addr) -> Cmd {
    let timeout = PING_TIMEOUT_SECS.to_string();
    let flag = match platform {
        Platform::MacOs => "-t",
        _ => "-W",
    };
    Cmd {
        program: "ping".to_string(),
        args: vec![
            "-c".to_string(),
            "1".to_string(),
            flag.to_string(),
            timeout,
            address.to_string(),
        ],
    }
}

/// How far the tunnel got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Interface up, hub answered.
    Working,
    /// `wg-quick up` failed; there is no interface.
    NotUp(WgError),
    /// The interface is up but the hub did not answer.
    NoAnswer(String),
    /// No `ping` on this machine, so nothing was verified.
    Unverified,
}

impl Outcome {
    pub fn is_working(&self) -> bool {
        matches!(self, Outcome::Working)
    }
}

/// Brings the interface up and checks it.
///
/// **Human verification needed**: runs `wg-quick` and `ping`, which
/// need a real kernel, root, and a hub at the other end.
pub fn run(wg_config_path: &Path, server_address: Ipv4Addr, path_var: &str) -> Outcome {
    let platform = wg::platform_from(std::env::consts::OS);
    if let Err(e) = wg::run(&wg::quick_up(wg_config_path), None) {
        return Outcome::NotUp(e);
    }
    if wg::find_in_path(path_var, "ping").is_none() {
        return Outcome::Unverified;
    }
    match wg::run(&ping_command(platform, server_address), None) {
        Ok(_) => Outcome::Working,
        Err(WgError::Failed { stderr, .. }) => Outcome::NoAnswer(stderr),
        Err(e) => Outcome::NoAnswer(e.to_string()),
    }
}

/// What to tell the person, given how far it got.
///
/// Pure, and deliberately specific: "it didn't work" costs an evening,
/// while "open UDP 51820 on the server" costs a minute.
pub fn report(
    outcome: &Outcome,
    server_address: Ipv4Addr,
    endpoint: &str,
    config: &Path,
) -> String {
    match outcome {
        Outcome::Working => format!("The tunnel is up — {server_address} answers.\n"),
        Outcome::NotUp(e) => format!(
            "The device is registered and its config is written, but the interface did not \
             come up:\n\n     {e}\n\n\
             Bringing it up needs root, so try `sudo wg-quick up {config}`. If that says the \
             interface already exists, `sudo wg-quick down {config}` first.\n",
            config = config.display()
        ),
        Outcome::NoAnswer(detail) => format!(
            "The interface is up, but {server_address} did not answer{detail}.\n\n\
             Three things break this, in order of likelihood:\n\
             \x20 - the hub's firewall: {endpoint} has to be reachable, UDP\n\
             \x20 - the hub is not running: `systemctl status anago` on the server\n\
             \x20 - this network blocks outbound UDP, which a phone hotspot usually does not\n\n\
             The device is registered either way; nothing needs re-joining.\n",
            detail = if detail.is_empty() {
                String::new()
            } else {
                format!(" ({})", detail.trim())
            }
        ),
        Outcome::Unverified => format!(
            "The interface is up. `ping` is not installed here, so the tunnel was not \
             checked — try reaching {server_address} yourself.\n"
        ),
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Working => f.write_str("working"),
            Outcome::NotUp(e) => write!(f, "the interface did not come up: {e}"),
            Outcome::NoAnswer(_) => f.write_str("the hub did not answer"),
            Outcome::Unverified => f.write_str("not verified"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hub() -> Ipv4Addr {
        "10.100.0.1".parse().unwrap()
    }

    #[test]
    fn the_ping_flag_follows_the_platform() {
        // -W means seconds on Linux and milliseconds on macOS: the same
        // command line would wait 5ms on a Mac and report failure.
        assert_eq!(
            ping_command(Platform::Linux, hub()).display(),
            "ping -c 1 -W 5 10.100.0.1"
        );
        assert_eq!(
            ping_command(Platform::MacOs, hub()).display(),
            "ping -c 1 -t 5 10.100.0.1"
        );
        // One packet, so the command returns quickly either way.
        assert!(ping_command(Platform::Other, hub())
            .args
            .contains(&"1".to_string()));
    }

    #[test]
    fn a_working_tunnel_says_so_briefly() {
        let text = report(
            &Outcome::Working,
            hub(),
            "net.example.com:51820",
            Path::new("/etc/wireguard/anago.conf"),
        );
        assert_eq!(text, "The tunnel is up — 10.100.0.1 answers.\n");
    }

    #[test]
    fn a_failed_bring_up_points_at_root_and_the_command_to_retry() {
        let text = report(
            &Outcome::NotUp(WgError::Failed {
                line: "wg-quick up /etc/wireguard/anago.conf".to_string(),
                status: Some(1),
                stderr: "Operation not permitted".to_string(),
            }),
            hub(),
            "net.example.com:51820",
            Path::new("/etc/wireguard/anago.conf"),
        );
        assert!(
            text.contains("registered and its config is written"),
            "{text}"
        );
        assert!(
            text.contains("sudo wg-quick up /etc/wireguard/anago.conf"),
            "{text}"
        );
        assert!(
            text.contains("wg-quick down"),
            "an existing interface: {text}"
        );
        assert!(text.contains("Operation not permitted"), "{text}");
    }

    #[test]
    fn a_silent_hub_gets_the_three_things_that_cause_it() {
        let text = report(
            &Outcome::NoAnswer("100% packet loss".to_string()),
            hub(),
            "net.example.com:51820",
            Path::new("/etc/wireguard/anago.conf"),
        );
        // The endpoint, because the firewall rule is about that port.
        assert!(text.contains("net.example.com:51820"), "{text}");
        assert!(text.contains("UDP"), "{text}");
        assert!(text.contains("systemctl status anago"), "{text}");
        assert!(text.contains("100% packet loss"), "{text}");
        // And the reassurance that matters: the code is spent, and it
        // does not need to be spent again.
        assert!(text.contains("nothing needs re-joining"), "{text}");
    }

    #[test]
    fn a_machine_without_ping_is_told_what_was_not_checked() {
        let text = report(
            &Outcome::Unverified,
            hub(),
            "net.example.com:51820",
            Path::new("/etc/wireguard/anago.conf"),
        );
        assert!(text.contains("interface is up"), "{text}");
        assert!(text.contains("not checked"), "{text}");
        assert!(text.contains("10.100.0.1"), "{text}");
    }

    #[test]
    fn only_a_hub_that_answered_counts_as_working() {
        assert!(Outcome::Working.is_working());
        assert!(!Outcome::NoAnswer(String::new()).is_working());
        assert!(!Outcome::Unverified.is_working());
        assert!(!Outcome::NotUp(WgError::NotFound {
            tool: "wg-quick",
            hint: "install it"
        })
        .is_working());
    }
}
