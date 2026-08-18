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
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
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
    write_private_owned(path, contents, None)
}

/// [`write_private`], giving the result to `owner`.
///
/// The `fchown` happens on the temp file's own descriptor, before the
/// rename — so the file arrives at its name already belonging to the
/// right person, and there is no window where it exists under the final
/// name owned by root.
pub fn write_private_owned(
    path: &Path,
    contents: &str,
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    let tmp = temp_sibling(path)?;

    let mut file = create_private_new(&tmp)?;
    file.write_all(contents.as_bytes())?;
    if let Some((uid, gid)) = owner {
        give_fd_to(&file, uid, gid)?;
    }
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

/// Creates a directory and everything above it, then makes the leaf
/// 0700. Existing directories are left alone apart from that mode.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(PRIVATE_DIR_MODE))
}

/// Publishes a *new* file, 0600, refusing to replace an existing one.
///
/// [`write_private`] replaces whatever is there, which is right for a
/// state file anago owns. This is for the other case — creating
/// something that must not exist yet — where losing a race has to be an
/// error rather than a silent overwrite.
pub fn create_new_private(path: &Path, contents: &str) -> io::Result<()> {
    create_new_private_owned(path, contents, None)
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

/// Creates `path` fresh, 0600, failing if it already exists.
///
/// `mode()` only applies to a file this call creates, so opening an
/// existing temp file — one a killed run left behind, possibly 0644 —
/// would write secrets into whatever permissions that file already had
/// and only tighten them afterwards. Removing first and creating
/// exclusively means the content never exists under a looser mode, and
/// `O_NOFOLLOW` means a symlink left in its place is not followed.
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
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
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

/// Creates a file and hands it to `uid`:`gid` through the descriptor it
/// was created with.
///
/// `fchown` on the open descriptor, never `chown` on the path: between
/// creating a file and chowning it by name, the name can be replaced
/// with a link to something else. The descriptor cannot be.
///
/// **Human verification needed**: giving a file away needs root, so
/// this only takes effect on a real machine under sudo.
pub fn create_new_private_owned(
    path: &Path,
    contents: &str,
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    // Written in full, given away, and only then published under its
    // real name. Creating the final path directly would leave a partial
    // file there if the process died mid-write — and since this is what
    // `server init` uses for the state file and the wg config, the next
    // run would refuse to start over a stub it cannot use.
    let tmp = unique_temp_sibling(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        // A path under someone's home may be a symlink they placed
        // there; root following it would write wherever it points.
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    let written = file
        .write_all(contents.as_bytes())
        .and_then(|()| match owner {
            // Before the link, so the file is never visible under its
            // real name owned by anybody else.
            Some((uid, gid)) => give_fd_to(&file, uid, gid),
            None => Ok(()),
        })
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    // `link(2)` fails if the name is taken, which is what makes this
    // publish both complete and no-clobber. A `rename` would clobber.
    let linked = fs::hard_link(&tmp, path);
    let _ = fs::remove_file(&tmp);
    linked?;
    sync_parent(path);
    Ok(())
}

/// `path` with this process's id and `.tmp` appended, so two racing
/// writers never share scratch space.
fn unique_temp_sibling(path: &Path) -> io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{path:?} has no file name"),
        )
    })?;
    let mut tmp = name.to_os_string();
    tmp.push(format!(".{}.tmp", std::process::id()));
    Ok(path.with_file_name(tmp))
}

/// `fchown` on an open file.
pub fn give_fd_to(file: &File, uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: the descriptor is owned by `file` and valid for the call.
    let result = unsafe { libc::fchown(file.as_raw_fd(), uid, gid) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// A directory, opened once and held open.
///
/// Everything a root process does inside somebody's home goes through
/// one of these. Checking a path and then using the path again is a
/// race the person who owns that path can win: rename `~/.config/anago`
/// between the two, point it at `/etc`, and the next `open` lands
/// wherever they chose. A descriptor cannot be redirected — `openat`
/// and friends resolve relative to the inode this handle already holds,
/// so the check and the work are about the same directory by
/// construction.
#[derive(Debug)]
pub struct DirHandle {
    fd: OwnedFd,
    path: PathBuf,
}

impl DirHandle {
    /// Opens `path`, refusing symlinks, and confirms `uid` owns it.
    ///
    /// `O_NOFOLLOW` here rejects a symlink *at* the final component;
    /// the owner check is what makes a directory swapped in earlier
    /// useless, since it would have to belong to the same person.
    pub fn open_owned(path: &Path, uid: u32) -> io::Result<DirHandle> {
        let handle = DirHandle::open(path)?;
        if handle.owner()? != uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} is not owned by uid {uid}", path.display()),
            ));
        }
        Ok(handle)
    }

    /// Opens `path` as a directory, refusing symlinks.
    pub fn open(path: &Path) -> io::Result<DirHandle> {
        let c_path = c_path(path)?;
        // SAFETY: the string is NUL-terminated and outlives the call.
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor this call owns.
        Ok(DirHandle {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The uid that owns the directory this handle holds.
    pub fn owner(&self) -> io::Result<u32> {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: the descriptor is valid and `stat` is ours.
        let result = unsafe { libc::fstat(self.fd.as_raw_fd(), &mut stat) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(stat.st_uid)
    }

    /// Whether `name` exists here, without following a symlink at it.
    pub fn exists(&self, name: &str) -> io::Result<bool> {
        let c_name = c_name(name)?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: both pointers are valid for the call.
        let result = unsafe {
            libc::fstatat(
                self.fd.as_raw_fd(),
                c_name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::NotFound => Ok(false),
            _ => Err(error),
        }
    }

    /// Reads a file here.
    pub fn read_to_string(&self, name: &str) -> io::Result<String> {
        let mut file = self.open_file(name, libc::O_RDONLY, 0)?;
        let mut text = String::new();
        std::io::Read::read_to_string(&mut file, &mut text)?;
        Ok(text)
    }

    /// Creates `name` with `contents`, 0600, failing if it exists.
    ///
    /// Complete-then-publish, like [`create_new_private`]: the content
    /// goes to a temp name in this same directory and is linked into
    /// place, so a crash leaves no half-written file under the real
    /// name and a race loses rather than clobbers.
    pub fn create_new_private(
        &self,
        name: &str,
        contents: &str,
        owner: Option<(u32, u32)>,
    ) -> io::Result<()> {
        let tmp = temp_name(name);
        self.remove(&tmp).or_else(ignore_missing)?;
        self.write_temp(&tmp, contents, owner)?;

        let linked = self.link(&tmp, name);
        let _ = self.remove(&tmp);
        linked?;
        self.sync();
        Ok(())
    }

    /// Replaces `name` with `contents`, 0600, atomically.
    pub fn write_private(
        &self,
        name: &str,
        contents: &str,
        owner: Option<(u32, u32)>,
    ) -> io::Result<()> {
        let tmp = temp_name(name);
        self.remove(&tmp).or_else(ignore_missing)?;
        self.write_temp(&tmp, contents, owner)?;

        let renamed = self.rename(&tmp, name);
        if renamed.is_err() {
            let _ = self.remove(&tmp);
        }
        renamed?;
        self.sync();
        Ok(())
    }

    /// Takes an exclusive lock on `name`, creating it if needed.
    ///
    /// `owner` applies only to a file this call creates: an existing
    /// lock file already belongs to somebody, and handing it over would
    /// be a way to have root give away whatever is there.
    pub fn try_lock(&self, name: &str, owner: Option<(u32, u32)>) -> io::Result<Option<FileLock>> {
        let file = match self.open_file(
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            PRIVATE_FILE_MODE,
        ) {
            Ok(file) => {
                if let Some((uid, gid)) = owner {
                    give_fd_to(&file, uid, gid)?;
                }
                file
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                self.open_file(name, libc::O_WRONLY | libc::O_NOFOLLOW, 0)?
            }
            Err(e) => return Err(e),
        };
        match flock(&file, libc::LOCK_EX | libc::LOCK_NB) {
            Ok(()) => Ok(Some(FileLock { file })),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Removes `name`.
    pub fn remove(&self, name: &str) -> io::Result<()> {
        let c_name = c_name(name)?;
        // SAFETY: the descriptor and the name are valid for the call.
        let result = unsafe { libc::unlinkat(self.fd.as_raw_fd(), c_name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn write_temp(&self, tmp: &str, contents: &str, owner: Option<(u32, u32)>) -> io::Result<()> {
        let mut file = self.open_file(
            tmp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            PRIVATE_FILE_MODE,
        )?;
        let written = file
            .write_all(contents.as_bytes())
            .and_then(|()| match owner {
                // Before it is published, so the file never exists
                // under its real name owned by anybody else.
                Some((uid, gid)) => give_fd_to(&file, uid, gid),
                None => Ok(()),
            })
            .and_then(|()| file.sync_all());
        if written.is_err() {
            let _ = self.remove(tmp);
        }
        written
    }

    fn open_file(&self, name: &str, flags: i32, mode: u32) -> io::Result<File> {
        let c_name = c_name(name)?;
        // SAFETY: the descriptor and the name are valid for the call;
        // the returned descriptor is handed straight to `File`.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c_name.as_ptr(),
                flags | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor this call owns.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn link(&self, from: &str, to: &str) -> io::Result<()> {
        let (from, to) = (c_name(from)?, c_name(to)?);
        // SAFETY: all three arguments are valid for the call.
        let result = unsafe {
            libc::linkat(
                self.fd.as_raw_fd(),
                from.as_ptr(),
                self.fd.as_raw_fd(),
                to.as_ptr(),
                0,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let (from, to) = (c_name(from)?, c_name(to)?);
        // SAFETY: all three arguments are valid for the call.
        let result = unsafe {
            libc::renameat(
                self.fd.as_raw_fd(),
                from.as_ptr(),
                self.fd.as_raw_fd(),
                to.as_ptr(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Best-effort flush of the directory itself.
    fn sync(&self) {
        // SAFETY: the descriptor is valid.
        unsafe { libc::fsync(self.fd.as_raw_fd()) };
    }
}

/// The temp name a publish writes through, beside its target.
fn temp_name(name: &str) -> String {
    format!("{name}.{}.tmp", std::process::id())
}

fn ignore_missing(e: io::Error) -> io::Result<()> {
    if e.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(e)
    }
}

fn c_path(path: &Path) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL"))
}

/// A single path component — no separators, so it cannot escape the
/// directory the handle holds.
fn c_name(name: &str) -> io::Result<std::ffi::CString> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name:?} is not a file name"),
        ));
    }
    std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains a NUL"))
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
    ///
    /// Only tests take a lock this way. Every caller in the program
    /// waits instead: a `server init` that gave up because another one
    /// held the lock for a moment would be worse than one that waited.
    /// Keeping it here — rather than reimplementing `flock` in the
    /// tests — means the contention they check is this lock, not a
    /// lookalike.
    #[cfg(test)]
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

/// Opens the lock file, creating it if it is not there.
///
/// An existing lock file is opened without following symlinks: a
/// `join.lock` symlinked to `/etc/passwd` would otherwise have root
/// write to that file instead.
fn lock_file(path: &Path) -> io::Result<File> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => Ok(file),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path),
        Err(e) => Err(e),
    }
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
    fn a_new_file_is_published_privately() {
        let dir = TempDir::new();
        let path = dir.join("anago.conf");
        create_new_private(&path, "[Interface]\n").unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "[Interface]\n");
        assert_eq!(mode_of(&path), PRIVATE_FILE_MODE);
        // Nothing left over.
        let entries: Vec<String> = fs::read_dir(&dir.path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, ["anago.conf"]);
    }

    #[test]
    fn publishing_over_an_existing_file_is_refused_not_silent() {
        // The difference from write_private: losing this race must be
        // an error, and the file that was there must survive intact.
        let dir = TempDir::new();
        let path = dir.join("anago.conf");
        fs::write(&path, "someone else's interface").unwrap();

        let e = create_new_private(&path, "ours").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "someone else's interface"
        );
        assert!(!dir
            .join(&format!("anago.conf.{}.tmp", std::process::id()))
            .exists());
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
    fn a_file_can_be_created_and_handed_over_in_one_go() {
        // The interesting hand-over needs root; what runs here is the
        // create-and-keep path, plus the refusal to replace.
        let dir = TempDir::new();
        let path = dir.join("device.json");
        create_new_private_owned(&path, "{}", None).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{}");
        assert_eq!(mode_of(&path), PRIVATE_FILE_MODE);

        assert_eq!(
            create_new_private_owned(&path, "{}", None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn a_new_file_appears_only_when_it_is_complete() {
        // Regression: writing straight to the final path left a partial
        // file there if the process died — and `server init` then
        // refused to run again over its own stub.
        let dir = TempDir::new();
        let path = dir.join("state.json");
        create_new_private_owned(&path, "{\"version\":1}", None).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"version\":1}");

        // Nothing is left beside it, and a second publish is refused
        // rather than replacing what is there.
        let entries: Vec<String> = fs::read_dir(&dir.path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, ["state.json"]);
        assert_eq!(
            create_new_private_owned(&path, "other", None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"version\":1}");
    }

    #[test]
    fn a_symlink_is_never_followed_when_creating() {
        // `~/.config/anago/device.json` pointing at /etc/passwd is a
        // way to have a root process write where it must not.
        let dir = TempDir::new();
        let target = dir.join("target");
        fs::write(&target, "do not touch").unwrap();
        let link = dir.join("device.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let e = create_new_private_owned(&link, "ours", None).unwrap_err();
        assert!(matches!(e.kind(), io::ErrorKind::AlreadyExists), "{e:?}");
        assert_eq!(fs::read_to_string(&target).unwrap(), "do not touch");

        // And the same for the write path used elsewhere.
        let _ = write_private(&link, "ours");
        assert_eq!(fs::read_to_string(&target).unwrap(), "do not touch");
    }

    #[test]
    fn a_directory_is_only_opened_when_the_person_owns_it() {
        let dir = TempDir::new();
        let uid = unsafe { libc::getuid() };
        assert!(DirHandle::open_owned(&dir.path, uid).is_ok());
        // Somebody else's: not ours to write into.
        let e = DirHandle::open_owned(&dir.path, uid + 1).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);

        // A symlink to a directory is not a directory here, whatever it
        // points at — otherwise a `~/.config/anago` aimed at /etc would
        // have root write there.
        let link = dir.join("link");
        std::os::unix::fs::symlink("/etc", &link).unwrap();
        assert!(DirHandle::open_owned(&link, uid).is_err());

        // A file is not a directory, and a missing path is an error
        // rather than a silent success.
        let file = dir.join("file");
        fs::write(&file, "x").unwrap();
        assert!(DirHandle::open_owned(&file, uid).is_err());
        assert!(DirHandle::open_owned(&dir.join("missing"), uid).is_err());
    }

    #[test]
    fn a_lock_file_that_is_a_symlink_is_refused() {
        // `join.lock` symlinked at /etc/passwd would otherwise have a
        // root process open that file — and, with an owner to hand it
        // to, give it away.
        let dir = TempDir::new();
        let target = dir.join("target");
        fs::write(&target, "do not touch").unwrap();
        let link = dir.join("state.lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let e = FileLock::acquire(&link).unwrap_err();
        assert!(
            matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::EMLINK)),
            "{e:?}"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "do not touch");
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
