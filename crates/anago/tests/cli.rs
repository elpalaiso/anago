//! Process-level checks: what the shell actually sees.
//!
//! The routing rules themselves are unit-tested in `cli`; these run the
//! real binary so the exit codes a script would branch on cannot drift
//! from the ones `cli::exit_code` decides.

use std::process::Command;

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_anago"))
        .args(args)
        .output()
        .expect("failed to run anago");
    (
        output.status.code().expect("terminated by a signal"),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn help_and_version_succeed() {
    let (code, stdout, _) = run(&["--version"]);
    assert_eq!(code, 0);
    assert!(stdout.starts_with("anago "), "{stdout}");

    let (code, stdout, _) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("anago server init"), "{stdout}");

    // Help still wins after a command and its flags.
    let (code, stdout, _) = run(&["server", "init", "--domain", "net.example.com", "--help"]);
    assert_eq!(code, 0, "{stdout}");
    assert!(stdout.starts_with("usage: anago server init"), "{stdout}");
}

#[test]
fn a_later_milestone_command_exits_one_not_two() {
    // `anago sync` used to answer this way and is a real command now;
    // `ping` is the one still waiting for its milestone.
    let (code, _, stderr) = run(&["ping", "macbook"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("arrives in M3"), "{stderr}");
    // Understood, so no "try --help" nudge.
    assert!(!stderr.contains("try `anago --help`"), "{stderr}");
}

#[test]
fn a_flag_value_that_is_not_ascii_is_an_error_and_not_a_crash() {
    // Regression: `--interval` used to take its unit off by byte, so a
    // value whose last character is multi-byte split inside that
    // character and panicked — which a person sees as exit 101 and a
    // backtrace rather than as the mistake they made.
    let (code, _, stderr) = run(&["sync", "--install-timer", "--interval", "5분"]);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("--interval"), "{stderr}");
    assert!(stderr.contains("no unit"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn a_typo_exits_two() {
    let (code, _, stderr) = run(&["snyc"]);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("unknown command"), "{stderr}");
    assert!(stderr.contains("try `anago --help`"), "{stderr}");

    let (code, _, stderr) = run(&[
        "server",
        "init",
        "--port",
        "0",
        "--domain",
        "net.example.com",
        "--tls-cert",
        "/c.pem",
        "--tls-key",
        "/k.pem",
    ]);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("1-65535"), "{stderr}");
}
