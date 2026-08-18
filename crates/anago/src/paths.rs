//! Where anago's files live (DESIGN.md §9).
//!
//! Every path is derived from a base this module is *given*, so the
//! rules are pure functions and the tests below never touch the
//! environment. Reading `HOME`/`XDG_CONFIG_HOME` happens in one thin
//! wrapper, [`client_config_dir_from_env`], which does nothing but hand
//! those values to the pure resolver.

use std::env;
use std::fmt;
use std::path::{Path, PathBuf};

/// Server state directory (§9). Root-owned on the VPS.
pub const DEFAULT_SERVER_ROOT: &str = "/var/lib/anago";

/// Where wg-quick keeps interface configs on Linux and on macOS
/// (Homebrew's wireguard-tools uses the same path).
pub const DEFAULT_WG_DIR: &str = "/etc/wireguard";

/// Interface name, and therefore the config's file stem: `anago.conf`
/// makes the interface `anago` for `wg-quick up anago`.
pub const WG_INTERFACE: &str = "anago";

/// Paths under the server's state directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerPaths {
    root: PathBuf,
}

impl ServerPaths {
    /// Takes the root rather than reading it, so a test can hand in a
    /// temporary directory and the production caller hands in
    /// [`DEFAULT_SERVER_ROOT`].
    pub fn new(root: impl Into<PathBuf>) -> ServerPaths {
        ServerPaths { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The single state file (§9).
    pub fn state_file(&self) -> PathBuf {
        self.root.join("state.json")
    }

    /// Scratch name for the tmp+rename write. Deliberately a sibling of
    /// the state file: rename is only atomic within one filesystem.
    pub fn state_tmp(&self) -> PathBuf {
        self.root.join("state.json.tmp")
    }

    /// The flock target that serializes concurrent joins (§13).
    ///
    /// A separate file, not `state.json` itself: the writer replaces
    /// that file by rename, so a lock held on it would end up on an
    /// unlinked inode while the next writer locks the new one.
    pub fn state_lock(&self) -> PathBuf {
        self.root.join("state.lock")
    }

    /// ACME account and certificates (§9). Empty in M0, which takes
    /// `--tls-cert`/`--tls-key` and only records those paths.
    pub fn tls_dir(&self) -> PathBuf {
        self.root.join("tls")
    }
}

/// Paths under a device's config directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPaths {
    dir: PathBuf,
}

impl ClientPaths {
    pub fn new(dir: impl Into<PathBuf>) -> ClientPaths {
        ClientPaths { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Domain, device token, assigned address, server public key —
    /// 0600 (§9). The wg private key is not in here; it lives in the wg
    /// config and nowhere else.
    pub fn device_file(&self) -> PathBuf {
        self.dir.join("device.json")
    }
}

/// The wg-quick config for the anago interface, under `dir`.
pub fn wg_config(dir: impl AsRef<Path>) -> PathBuf {
    dir.as_ref().join(format!("{WG_INTERFACE}.conf"))
}

/// Resolves a device's config directory from the two environment
/// variables that decide it — passed in, not read here.
///
/// The rule is DESIGN.md §9: `$XDG_CONFIG_HOME/anago` when that is set
/// and absolute, otherwise `$HOME/.config/anago`. `~/.config` is XDG's
/// own default, so honouring a moved `XDG_CONFIG_HOME` is what the
/// documented path means rather than a departure from it.
///
/// A relative `XDG_CONFIG_HOME` is ignored rather than resolved against
/// the current directory, which would put a device's token wherever the
/// user happened to `cd`.
pub fn client_config_dir(
    xdg_config_home: Option<&str>,
    home: Option<&str>,
) -> Result<ClientPaths, PathError> {
    if let Some(xdg) = xdg_config_home {
        let xdg = Path::new(xdg);
        if xdg.is_absolute() {
            return Ok(ClientPaths::new(xdg.join("anago")));
        }
    }
    match home.filter(|home| Path::new(home).is_absolute()) {
        Some(home) => Ok(ClientPaths::new(
            Path::new(home).join(".config").join("anago"),
        )),
        None => Err(PathError::NoHome),
    }
}

/// The one place that reads the environment.
pub fn client_config_dir_from_env() -> Result<ClientPaths, PathError> {
    let xdg = env::var("XDG_CONFIG_HOME").ok();
    let home = env::var("HOME").ok();
    client_config_dir(xdg.as_deref(), home.as_deref())
}

/// Why a path could not be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// Neither `XDG_CONFIG_HOME` nor `HOME` gave an absolute directory.
    NoHome,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::NoHome => write!(
                f,
                "cannot tell where your config directory is — set HOME or XDG_CONFIG_HOME"
            ),
        }
    }
}

impl std::error::Error for PathError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> ServerPaths {
        ServerPaths::new(DEFAULT_SERVER_ROOT)
    }

    #[test]
    fn server_files_hang_off_the_root_it_is_given() {
        let paths = server();
        assert_eq!(paths.state_file(), Path::new("/var/lib/anago/state.json"));
        assert_eq!(
            paths.state_tmp(),
            Path::new("/var/lib/anago/state.json.tmp")
        );
        assert_eq!(paths.state_lock(), Path::new("/var/lib/anago/state.lock"));
        assert_eq!(paths.tls_dir(), Path::new("/var/lib/anago/tls"));
        assert_eq!(paths.root(), Path::new("/var/lib/anago"));
    }

    #[test]
    fn a_test_can_point_the_server_at_a_temporary_root() {
        // The reason the root is an argument: no test needs to be root,
        // and none of them touch /var.
        let paths = ServerPaths::new("/tmp/anago-test-123");
        assert_eq!(
            paths.state_file(),
            Path::new("/tmp/anago-test-123/state.json")
        );
        assert!(paths.state_file().starts_with("/tmp/anago-test-123"));
    }

    #[test]
    fn the_temp_file_is_a_sibling_of_the_state_file() {
        // tmp+rename is only atomic within one filesystem.
        let paths = server();
        assert_eq!(paths.state_tmp().parent(), paths.state_file().parent());
        assert_ne!(paths.state_tmp(), paths.state_file());
    }

    #[test]
    fn the_lock_is_not_the_file_being_replaced() {
        // Locking state.json itself would leave each writer holding an
        // unlinked inode after the first rename.
        let paths = server();
        assert_ne!(paths.state_lock(), paths.state_file());
        assert_eq!(paths.state_lock().parent(), paths.state_file().parent());
    }

    #[test]
    fn the_wg_config_names_the_interface() {
        // wg-quick takes the file stem as the interface name.
        assert_eq!(
            wg_config(DEFAULT_WG_DIR),
            Path::new("/etc/wireguard/anago.conf")
        );
        assert_eq!(
            wg_config("/tmp/wg")
                .file_stem()
                .and_then(|stem| stem.to_str()),
            Some(WG_INTERFACE)
        );
    }

    #[test]
    fn xdg_config_home_wins_when_it_is_absolute() {
        let paths = client_config_dir(Some("/home/jo/.config"), Some("/home/jo")).unwrap();
        assert_eq!(paths.dir(), Path::new("/home/jo/.config/anago"));
        assert_eq!(
            paths.device_file(),
            Path::new("/home/jo/.config/anago/device.json")
        );

        // Even when it points somewhere unrelated to HOME.
        let paths = client_config_dir(Some("/mnt/keys"), Some("/home/jo")).unwrap();
        assert_eq!(paths.dir(), Path::new("/mnt/keys/anago"));
    }

    #[test]
    fn home_is_the_fallback() {
        let paths = client_config_dir(None, Some("/home/jo")).unwrap();
        assert_eq!(paths.dir(), Path::new("/home/jo/.config/anago"));
        assert_eq!(
            paths.device_file(),
            Path::new("/home/jo/.config/anago/device.json")
        );
    }

    #[test]
    fn a_relative_xdg_value_is_ignored_not_resolved() {
        // Resolving it would drop a device's token wherever the user
        // happened to be standing.
        for xdg in ["config", "./config", ""] {
            let paths = client_config_dir(Some(xdg), Some("/home/jo")).unwrap();
            assert_eq!(
                paths.dir(),
                Path::new("/home/jo/.config/anago"),
                "xdg={xdg:?}"
            );
        }
    }

    #[test]
    fn a_relative_or_missing_home_is_an_error_not_a_guess() {
        assert_eq!(client_config_dir(None, None), Err(PathError::NoHome));
        assert_eq!(client_config_dir(None, Some("jo")), Err(PathError::NoHome));
        assert_eq!(client_config_dir(Some("cfg"), None), Err(PathError::NoHome));
        assert_eq!(
            PathError::NoHome.to_string(),
            "cannot tell where your config directory is — set HOME or XDG_CONFIG_HOME"
        );
    }

    #[test]
    fn trailing_slashes_do_not_double_up() {
        let paths = client_config_dir(Some("/home/jo/.config/"), None).unwrap();
        assert_eq!(paths.dir(), Path::new("/home/jo/.config/anago"));
        assert_eq!(
            ServerPaths::new("/var/lib/anago/").state_file(),
            Path::new("/var/lib/anago/state.json")
        );
    }
}
