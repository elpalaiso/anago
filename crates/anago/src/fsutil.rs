//! File handling for anago's own files (DESIGN.md §9, §13).
//!
//! Three rules live here, and nothing else does them by hand:
//!
//! - **atomic writes**: content goes to a sibling temp file, gets
//!   flushed, then renames over the target. A crash mid-write leaves
//!   the old file intact rather than a truncated state file.
//! - **0600 from birth**: the mode is set in the open flags, not with a
//!   `chmod` afterwards — a private key must never exist as
//!   world-readable, not even for a microsecond.
//! - **flock**: concurrent joins are rare but real, so the server holds
//!   an exclusive lock across read-modify-write (§13).
//!
//! Unix only, which is the M0 target (§13: Windows is out of scope).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Mode for files holding secrets: state file, device token, wg config.
pub const PRIVATE_FILE_MODE: u32 = 0o600;

/// Mode for the directories those files sit in.
pub const PRIVATE_DIR_MODE: u32 = 0o700;

/// Writes `contents` to `path` atomically, 0600.
///
/// The temp file is a sibling because `rename(2)` is only atomic within
/// one filesystem — a temp under `/tmp` would silently degrade to a
/// copy across a mount boundary.
pub fn write_private(path: &Path, contents: &str) -> io::Result<()> {
    let tmp = temp_sibling(path)?;

    let mut file = create_private_new(&tmp)?;
    file.write_all(contents.as_bytes())?;
    // Durability before visibility: rename must not expose a file whose
    // contents are still in the page cache.
    file.sync_all()?;
    drop(file);

    match fs::rename(&tmp, path) {
        Ok(()) => {
            sync_parent(path);
            Ok(())
        }
        Err(e) => {
            // Leave nothing half-written behind for the next run to
            // trip over.
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Creates `path` fresh, 0600, failing if it already exists.
///
/// `mode()` only applies to a file this call creates, so opening an
/// existing temp file — one a killed run left behind, possibly 0644 —
/// would write secrets into whatever permissions that file already had
/// and only tighten them afterwards. Removing first and creating
/// exclusively means the content never exists under a looser mode.
fn create_private_new(path: &Path) -> io::Result<File> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
}

/// Creates a directory and everything above it, then makes the leaf
/// 0700. Existing directories are left alone apart from that mode.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(PRIVATE_DIR_MODE))
}

/// `path` with `.tmp` appended to its file name.
fn temp_sibling(path: &Path) -> io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{path:?} has no file name"),
        )
    })?;
    let mut tmp = name.to_os_string();
    tmp.push(".tmp");
    Ok(path.with_file_name(tmp))
}

/// Best-effort directory flush so the rename itself survives a power
/// cut. Failure is ignored: the data is already durable, and some
/// filesystems refuse to fsync a directory.
fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

/// An exclusive `flock(2)` on a lock file, released when dropped.
///
/// Held around the server's read-modify-write of the state file so two
/// simultaneous joins cannot both allocate `.2` (§13). The lock lives
/// on its own file, never on `state.json`, which gets replaced by
/// rename — a lock on a replaced file ends up on an unlinked inode.
#[derive(Debug)]
pub struct FileLock {
    file: File,
}

impl FileLock {
    /// Waits for the lock.
    pub fn acquire(path: &Path) -> io::Result<FileLock> {
        let file = lock_file(path)?;
        flock(&file, libc::LOCK_EX)?;
        Ok(FileLock { file })
    }

    /// Takes the lock if it is free, `None` if someone else holds it.
    pub fn try_acquire(path: &Path) -> io::Result<Option<FileLock>> {
        let file = lock_file(path)?;
        match flock(&file, libc::LOCK_EX | libc::LOCK_NB) {
            Ok(()) => Ok(Some(FileLock { file })),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // Closing the descriptor would release it anyway; unlocking
        // explicitly keeps the release at a point we chose.
        let _ = flock(&self.file, libc::LOCK_UN);
    }
}

fn lock_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
}

fn flock(file: &File, operation: i32) -> io::Result<()> {
    // SAFETY: `file` owns a valid descriptor for the duration of the
    // call, and `operation` is one of libc's LOCK_* constants.
    let result = unsafe { libc::flock(file.as_raw_fd(), operation) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A directory under the system temp dir, removed on drop. No env
    /// is read or written beyond `TMPDIR`, which we only read.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> TempDir {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("anago-fsutil-{}-{unique}", std::process::id()));
            fs::create_dir_all(&path).expect("temp dir");
            TempDir { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[test]
    fn writes_a_private_file() {
        let dir = TempDir::new();
        let path = dir.join("state.json");
        write_private(&path, "{\"version\":1}").unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"version\":1}");
        assert_eq!(mode_of(&path), PRIVATE_FILE_MODE);
    }

    #[test]
    fn leaves_no_temp_file_behind() {
        let dir = TempDir::new();
        let path = dir.join("state.json");
        write_private(&path, "one").unwrap();

        let entries: Vec<String> = fs::read_dir(&dir.path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, ["state.json"]);
    }

    #[test]
    fn overwriting_replaces_the_whole_file() {
        let dir = TempDir::new();
        let path = dir.join("state.json");
        write_private(&path, "a longer first version").unwrap();
        write_private(&path, "short").unwrap();

        // Not a partial overwrite of the longer content.
        assert_eq!(fs::read_to_string(&path).unwrap(), "short");
        assert_eq!(mode_of(&path), PRIVATE_FILE_MODE);
    }

    #[test]
    fn a_loose_target_mode_is_tightened_on_rewrite() {
        let dir = TempDir::new();
        let path = dir.join("state.json");
        write_private(&path, "first").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_private(&path, "second").unwrap();
        assert_eq!(
            mode_of(&path),
            PRIVATE_FILE_MODE,
            "rewrite must not inherit 0644"
        );
    }

    #[test]
    fn a_leftover_temp_file_does_not_block_a_write() {
        let dir = TempDir::new();
        let path = dir.join("state.json");
        fs::write(dir.join("state.json.tmp"), "junk from a killed process").unwrap();

        write_private(&path, "fresh").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "fresh");
        assert!(!dir.join("state.json.tmp").exists());
    }

    #[test]
    fn a_leftover_temp_never_lends_its_permissions_to_the_content() {
        // Regression: `mode()` applies only on creation, so reusing a
        // 0644 temp would put the state file's secrets on disk
        // world-readable until a later chmod.
        let dir = TempDir::new();
        let tmp = dir.join("state.json.tmp");
        fs::write(&tmp, "junk").unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o666)).unwrap();

        let file = create_private_new(&tmp).unwrap();
        assert_eq!(
            file.metadata().unwrap().permissions().mode() & 0o777,
            PRIVATE_FILE_MODE,
            "content would have been written under the old mode"
        );
        assert_eq!(
            fs::read_to_string(&tmp).unwrap(),
            "",
            "the old content survived"
        );
    }

    #[test]
    fn a_loose_leftover_temp_does_not_reach_the_target() {
        let dir = TempDir::new();
        let path = dir.join("state.json");
        let tmp = dir.join("state.json.tmp");
        fs::write(&tmp, "junk from a killed process").unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o666)).unwrap();

        write_private(&path, "secret").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "secret");
        assert_eq!(mode_of(&path), PRIVATE_FILE_MODE);
        assert!(!tmp.exists());
    }

    #[test]
    fn the_temp_file_is_a_sibling_so_rename_stays_atomic() {
        let path = Path::new("/var/lib/anago/state.json");
        assert_eq!(
            temp_sibling(path).unwrap(),
            Path::new("/var/lib/anago/state.json.tmp")
        );
        assert!(temp_sibling(Path::new("/")).is_err());
    }

    #[test]
    fn writing_into_a_missing_directory_fails_loudly() {
        let dir = TempDir::new();
        let path = dir.join("nope").join("state.json");
        let e = write_private(&path, "x").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn creates_private_directories() {
        let dir = TempDir::new();
        let nested = dir.join("var").join("lib").join("anago");
        ensure_private_dir(&nested).unwrap();
        assert_eq!(mode_of(&nested), PRIVATE_DIR_MODE);

        // Idempotent, and tightens a directory that already exists.
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&nested).unwrap();
        assert_eq!(mode_of(&nested), PRIVATE_DIR_MODE);
    }

    #[test]
    fn a_held_lock_keeps_everyone_else_out() {
        let dir = TempDir::new();
        let path = dir.join("state.lock");

        let held = FileLock::acquire(&path).unwrap();
        // flock is per-descriptor, so a second attempt — even in this
        // process — is the same contention the second join would see.
        assert!(FileLock::try_acquire(&path).unwrap().is_none());

        drop(held);
        assert!(FileLock::try_acquire(&path).unwrap().is_some());
    }

    #[test]
    fn the_lock_file_is_private_and_survives_relocking() {
        let dir = TempDir::new();
        let path = dir.join("state.lock");

        {
            let _lock = FileLock::acquire(&path).unwrap();
            assert_eq!(mode_of(&path), PRIVATE_FILE_MODE);
        }
        // Re-acquiring reuses the file rather than failing on it.
        let _again = FileLock::acquire(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn a_lock_does_not_disturb_the_state_file_beside_it() {
        // The whole point of a separate lock file: writes replace
        // state.json by rename while the lock stays put.
        let dir = TempDir::new();
        let state = dir.join("state.json");
        let lock = dir.join("state.lock");

        let held = FileLock::acquire(&lock).unwrap();
        write_private(&state, "first").unwrap();
        write_private(&state, "second").unwrap();
        assert!(FileLock::try_acquire(&lock).unwrap().is_none());

        drop(held);
        assert_eq!(fs::read_to_string(&state).unwrap(), "second");
        assert!(FileLock::try_acquire(&lock).unwrap().is_some());
    }
}
