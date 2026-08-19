//! Who starts `anago server run` and brings it back after a reboot —
//! the hub's residency (DESIGN.md §11.1 결정 3).
//!
//! - **Linux**: the systemd unit (M0's path, unchanged).
//! - **Windows**: a real Windows service through the SCM. Login-free
//!   start and reboot survival are the service manager's job; a startup
//!   shortcut would give neither.
//! - **macOS**: a LaunchDaemon — the same machinery the sync timer
//!   already uses, which is what makes a mac mini hub first-class.
//!
//! Command assembly is pure and unit-tested; running things is not.

use std::path::Path;

#[cfg(windows)]
use crate::wg::Cmd;

/// The Windows service name — also the tunnel's, so `sc query anago`
/// and `wg show anago` talk about the same hub.
#[cfg(windows)]
pub const SERVICE_NAME: &str = "anago";

/// Whether this host has a service manager anago knows how to drive.
pub fn is_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::systemd::is_available()
    }
    #[cfg(any(target_os = "macos", windows))]
    {
        true // launchd / the SCM *is* the operating system here
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        false
    }
}

/// Installs and starts the hub service, returning what to tell the
/// operator. The error is a string for init's warning list: the hub is
/// configured either way — only the babysitter is missing, and the
/// operator can still run it by hand.
pub fn install(
    exe: &Path,
    root: &Path,
    wg_dir: &Path,
    tls_cert: &Path,
    tls_key: &Path,
) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        let path = crate::systemd::install(
            exe,
            root,
            wg_dir,
            tls_cert,
            tls_key,
            Path::new(crate::systemd::UNIT_DIR),
        )
        .map_err(|e| e.to_string())?;
        Ok(crate::init::systemd_note(&path))
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (root, wg_dir, tls_cert, tls_key); // the exe re-derives them (§9)
        let plist = crate::launchd::server_plist(exe).map_err(|e| e.to_string())?;
        let path = crate::launchd::server_plist_path(Path::new(crate::launchd::DAEMONS_DIR));
        crate::fsutil::write_system(&path, &plist).map_err(|e| e.to_string())?;
        // A previous load must not shadow the file just written.
        let _ = crate::wg::run(&crate::launchd::bootout_server(), None);
        crate::wg::run(&crate::launchd::bootstrap(&path), None).map_err(|e| e.to_string())?;
        Ok(launchd_note(&path))
    }
    #[cfg(windows)]
    {
        let _ = (root, wg_dir, tls_cert, tls_key); // the exe re-derives them (§9)
        // Stop-delete-create rather than create-or-configure: the
        // sequence is idempotent, and each step that can fail on a
        // fresh machine ("service does not exist") is allowed to.
        let _ = crate::wg::run(&sc(&["stop", SERVICE_NAME]), None);
        let _ = crate::wg::run(&sc(&["delete", SERVICE_NAME]), None);
        crate::wg::run(&sc_create(exe), None).map_err(|e| e.to_string())?;
        crate::wg::run(&sc(&["start", SERVICE_NAME]), None).map_err(|e| e.to_string())?;
        Ok(windows_note())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (exe, root, wg_dir, tls_cert, tls_key);
        Err("this host has no service manager anago knows".to_string())
    }
}

/// `sc.exe <args…>`.
#[cfg(windows)]
fn sc(args: &[&str]) -> Cmd {
    Cmd::new("sc.exe", args)
}

/// `sc.exe create anago binPath= "<exe> server run --service" …`
///
/// The space after each `option=` is sc.exe's own calling convention.
/// The exe path rides inside the binPath value quoted, so a
/// `C:\Program Files\…` install survives.
#[cfg(windows)]
fn sc_create(exe: &Path) -> Cmd {
    Cmd {
        program: "sc.exe".to_string(),
        args: vec![
            "create".to_string(),
            SERVICE_NAME.to_string(),
            "binPath=".to_string(),
            format!("\"{}\" server run --service", exe.display()),
            "start=".to_string(),
            "auto".to_string(),
            "DisplayName=".to_string(),
            "anago WireGuard hub".to_string(),
        ],
    }
}

/// What `server init` says when the SCM took over.
#[cfg(windows)]
fn windows_note() -> String {
    format!(
        "The hub is running as the Windows service `{SERVICE_NAME}` and comes back on reboot.\n\
         \x20 check   sc query {SERVICE_NAME}\n\
         \x20 logs    {}\\anago\\service.log (written when something goes wrong)",
        std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string())
    )
}

/// What `server init` says when launchd took over.
#[cfg(target_os = "macos")]
fn launchd_note(plist: &Path) -> String {
    format!(
        "The hub is running as a LaunchDaemon ({}) and comes back on reboot.\n\
         \x20 check   sudo launchctl print {}\n\
         \x20 logs    {}",
        plist.display(),
        crate::launchd::server_target(),
        crate::launchd::SERVER_LOG,
    )
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn the_create_line_reads_like_scs_own_manual() {
        let cmd = sc_create(Path::new(r"C:\Program Files\anago\anago.exe"));
        let line = cmd.display();
        assert!(line.starts_with("sc.exe create anago binPath="), "{line}");
        assert!(
            line.contains(r#""C:\Program Files\anago\anago.exe" server run --service"#),
            "{line}"
        );
        assert!(line.contains("start= auto"), "{line}");
    }
}
