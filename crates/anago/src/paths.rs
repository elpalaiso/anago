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

    /// The single state file (§9).
    pub fn state_file(&self) -> PathBuf {
        self.root.join("state.json")
    }

    /// Where anago keeps the TLS material it issued itself (§9.1).
    ///
    /// Separate from a certificate a person gave anago with
    /// `--tls-cert`: those files stay where they are and anago only
    /// reads them. Everything under here is anago's to write and
    /// replace, which is also what makes going back to a manual
    /// certificate a matter of pointing the state elsewhere.
    // Both land in the issuance slice, which writes the account key
    // and the certificate under this directory.
    #[allow(dead_code)]
    pub fn tls_dir(&self) -> PathBuf {
        self.root.join("tls")
    }

    /// The certificate anago issued (§9).
    #[allow(dead_code)]
    pub fn certificate(&self) -> PathBuf {
        self.tls_dir().join("fullchain.pem")
    }

    /// Its private key.
    #[allow(dead_code)]
    pub fn private_key(&self) -> PathBuf {
        self.tls_dir().join("privkey.pem")
    }

    /// The ACME account credentials — the account key, and the URL that
    /// key is known to the CA by (§9.1).
    #[allow(dead_code)]
    pub fn account_key(&self) -> PathBuf {
        self.tls_dir().join("account.key")
    }

    /// The flock target that serializes **issuance** — the renewal
    /// timer against a `server renew` typed by hand (§9.1).
    ///
    /// Not the state lock: an issuance takes minutes (a CA looks, a
    /// record spreads), and holding the state lock for that would stop
    /// every join in the meantime. This one is held for the whole
    /// attempt and protects what an issuance owns — the account file,
    /// the certificate pair, and the CA's opinion of how often it is
    /// being asked.
    #[allow(dead_code)]
    pub fn issue_lock(&self) -> PathBuf {
        self.root.join("issue.lock")
    }

    /// The flock target that serializes concurrent joins (§13).
    ///
    /// A separate file, not `state.json` itself: the writer replaces
    /// that file by rename, so a lock held on it would end up on an
    /// unlinked inode while the next writer locks the new one.
    pub fn state_lock(&self) -> PathBuf {
        self.root.join("state.lock")
    }
}

/// The device file's name inside the config directory. A bare name,
/// because the work on it is done relative to a directory descriptor
/// rather than by path (see `fsutil::DirHandle`).
pub const DEVICE_FILE: &str = "device.json";

/// The join lock's name inside the config directory.
pub const JOIN_LOCK: &str = "join.lock";

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
        self.dir.join(DEVICE_FILE)
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

/// Whoever typed `sudo anago join`.
///
/// `join` needs root to write `/etc/wireguard`, but the device file it
/// writes belongs to the person, not to root. Without this, `sudo`
/// would put `device.json` in `/root/.config/anago` — where the same
/// person's later `anago ls` cannot find it — or leave it in their own
/// home owned by root, which they cannot read either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokingUser {
    pub uid: u32,
    pub gid: u32,
    /// The invoking user's home, from the password database.
    pub home: Option<PathBuf>,
}

/// Reads `SUDO_UID`/`SUDO_GID`, which sudo sets and nothing else does.
///
/// Values that are not numbers, or a uid of 0, mean there is nobody to
/// hand anything back to.
pub fn invoking_user(
    sudo_uid: Option<&str>,
    sudo_gid: Option<&str>,
    home: Option<PathBuf>,
) -> Option<InvokingUser> {
    let uid: u32 = sudo_uid?.parse().ok()?;
    if uid == 0 {
        return None;
    }
    let gid: u32 = sudo_gid.and_then(|gid| gid.parse().ok()).unwrap_or(uid);
    Some(InvokingUser { uid, gid, home })
}

/// [`invoking_user`] against this process's environment.
pub fn invoking_user_from_env() -> Option<InvokingUser> {
    let uid = env::var("SUDO_UID").ok();
    let gid = env::var("SUDO_GID").ok();
    let user = invoking_user(uid.as_deref(), gid.as_deref(), None)?;
    Some(InvokingUser {
        home: home_of(user.uid),
        ..user
    })
}

/// A uid's home directory, from the password database.
///
/// `SUDO_USER`'s home is the right base even when `HOME` says `/root`,
/// and `getpwuid_r` is the only way to ask.
fn home_of(uid: u32) -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;

    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0i8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `passwd` and `buffer` outlive the call, the buffer length
    // is its real length, and `result` is checked before `passwd` is
    // read.
    let code = unsafe {
        libc::getpwuid_r(
            uid,
            &mut passwd,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    if code != 0 || result.is_null() || passwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pw_dir` points into `buffer`, which is still alive.
    let dir = unsafe { CStr::from_ptr(passwd.pw_dir) };
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()));
    path.is_absolute().then_some(path)
}

/// Resolves the config directory the same way whether or not the
/// command was run through sudo.
///
/// `XDG_CONFIG_HOME` still wins when it is visible, so a person who
/// moved their config directory and runs `sudo -E anago join` gets the
/// same path their later `anago ls` will use. When sudo has stripped it
/// — the default — the invoking user's home from the password database
/// is the closest thing to the truth, and it matches what `anago ls`
/// resolves for somebody who has not moved anything.
///
/// Root's own `HOME` is never used while an invoking user is known:
/// `/root/.config/anago` is a place the person could not read anyway.
pub fn client_config_dir_for(
    xdg_config_home: Option<&str>,
    home: Option<&str>,
    invoking: Option<&InvokingUser>,
) -> Result<ClientPaths, PathError> {
    if let Some(xdg) = xdg_config_home {
        let xdg = Path::new(xdg);
        if xdg.is_absolute() {
            return Ok(ClientPaths::new(xdg.join("anago")));
        }
    }
    if let Some(sudo_home) = invoking.and_then(|user| user.home.as_deref()) {
        return Ok(ClientPaths::new(sudo_home.join(".config").join("anago")));
    }
    client_config_dir(None, home)
}

/// The one place that reads the environment.
pub fn client_config_dir_from_env() -> Result<ClientPaths, PathError> {
    let xdg = env::var("XDG_CONFIG_HOME").ok();
    let home = env::var("HOME").ok();
    client_config_dir_for(
        xdg.as_deref(),
        home.as_deref(),
        invoking_user_from_env().as_ref(),
    )
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
        assert_eq!(paths.state_lock(), Path::new("/var/lib/anago/state.lock"));
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
    fn the_files_in_the_config_directory_are_named_not_pathed() {
        // Both are opened relative to a directory descriptor (`openat`
        // against the handle `join` holds). A name with a separator in
        // it would escape that directory and put the check and the
        // write back on different inodes.
        for name in [DEVICE_FILE, JOIN_LOCK] {
            assert!(!name.contains('/'), "{name} is a path, not a name");
            assert_ne!(name, "..");
        }
        assert_ne!(DEVICE_FILE, JOIN_LOCK);
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
    fn sudo_and_plain_runs_land_in_the_same_directory() {
        // The device file is written by `sudo anago join` and read by a
        // plain `anago ls`: the two have to agree, or the token is
        // saved somewhere the next command will not look.
        let sudo = InvokingUser {
            uid: 501,
            gid: 20,
            home: Some(PathBuf::from("/home/jo")),
        };

        // Default sudo, which strips XDG: root's HOME is ignored in
        // favour of the invoking user's home — the same place a plain
        // run with HOME=/home/jo resolves.
        let under_sudo = client_config_dir_for(None, Some("/root"), Some(&sudo)).unwrap();
        let plain = client_config_dir_for(None, Some("/home/jo"), None).unwrap();
        assert_eq!(under_sudo.dir(), plain.dir());
        assert_eq!(under_sudo.dir(), Path::new("/home/jo/.config/anago"));

        // `sudo -E` keeps XDG_CONFIG_HOME, and a person who moved it
        // gets the same answer both ways.
        let under_sudo =
            client_config_dir_for(Some("/home/jo/cfg"), Some("/root"), Some(&sudo)).unwrap();
        let plain = client_config_dir_for(Some("/home/jo/cfg"), Some("/home/jo"), None).unwrap();
        assert_eq!(under_sudo.dir(), plain.dir());
        assert_eq!(under_sudo.dir(), Path::new("/home/jo/cfg/anago"));
    }

    #[test]
    fn sudo_variables_are_read_strictly() {
        assert_eq!(
            invoking_user(Some("501"), Some("20"), None),
            Some(InvokingUser {
                uid: 501,
                gid: 20,
                home: None
            })
        );
        // A missing gid falls back to the uid's own group.
        assert_eq!(
            invoking_user(Some("501"), None, None).map(|user| user.gid),
            Some(501)
        );
        // root running as root is nobody to hand files back to.
        assert_eq!(invoking_user(Some("0"), Some("0"), None), None);
        assert_eq!(invoking_user(None, Some("20"), None), None);
        assert_eq!(invoking_user(Some("nope"), None, None), None);
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
