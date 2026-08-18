//! The state file as the server sees it: read it, change it, write it
//! back — with the lock held the whole time (DESIGN.md §9, §13).
//!
//! Concurrency is the reason this is a type and not two functions. A
//! join is read-modify-write, and two of them racing would both read
//! "the lowest free address is .2". [`Store::lock`] takes the flock and
//! hands back a [`Guard`]; nothing is written until [`Guard::commit`],
//! so a handler that fails leaves the file exactly as it was.

use std::fmt;
use std::io;
use std::path::PathBuf;

use anago_core::state::{ServerState, StateError};

use crate::fsutil::{self, FileLock};
use crate::paths::ServerPaths;

/// The server's state directory.
#[derive(Debug, Clone)]
pub struct Store {
    paths: ServerPaths,
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Store {
        Store {
            paths: ServerPaths::new(root),
        }
    }

    pub fn paths(&self) -> &ServerPaths {
        &self.paths
    }

    /// Reads without taking the lock — for the read-only paths (`ls`,
    /// `peers`) where a slightly stale answer is fine and blocking a
    /// join would not be.
    pub fn read(&self) -> Result<ServerState, StoreError> {
        let path = self.paths.state_file();
        let text = std::fs::read_to_string(&path).map_err(|e| StoreError::Io {
            path: path.clone(),
            kind: e.kind(),
            source: e.to_string(),
        })?;
        ServerState::parse(&text).map_err(|error| StoreError::Parse { path, error })
    }

    /// Writes the state file atomically, 0600.
    pub fn write(&self, state: &ServerState) -> Result<(), StoreError> {
        let path = self.paths.state_file();
        fsutil::write_private(&path, &state.to_json_string()).map_err(|e| StoreError::Io {
            path,
            kind: e.kind(),
            source: e.to_string(),
        })
    }

    /// Takes the exclusive lock and reads the current state.
    pub fn lock(&self) -> Result<Guard<'_>, StoreError> {
        let lock_path = self.paths.state_lock();
        let lock = FileLock::acquire(&lock_path).map_err(|e| StoreError::Io {
            // A missing directory means this machine is not a hub, so
            // name the file that says so rather than the lock nobody
            // asked about.
            path: if e.kind() == io::ErrorKind::NotFound {
                self.paths.state_file()
            } else {
                lock_path
            },
            kind: e.kind(),
            source: e.to_string(),
        })?;
        let state = self.read()?;
        Ok(Guard {
            store: self,
            _lock: lock,
            state,
        })
    }
}

/// A held lock plus the state it protects. Dropping without
/// [`Guard::commit`] discards every change — the failure path of a
/// handler needs no cleanup.
pub struct Guard<'a> {
    store: &'a Store,
    _lock: FileLock,
    state: ServerState,
}

impl Guard<'_> {
    pub fn state(&self) -> &ServerState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut ServerState {
        &mut self.state
    }

    /// Writes the state back and releases the lock.
    pub fn commit(self) -> Result<(), StoreError> {
        self.store.write(&self.state)
    }
}

/// Why the state file could not be read or written.
#[derive(Debug, Clone, PartialEq)]
pub enum StoreError {
    Io {
        path: PathBuf,
        kind: io::ErrorKind,
        source: String,
    },
    Parse {
        path: PathBuf,
        error: StateError,
    },
}

impl StoreError {
    /// Whether the state file is simply not there yet — the answer
    /// `anago code` and the API need to say "run `anago server init`
    /// first" instead of dumping an io error.
    pub fn is_missing(&self) -> bool {
        matches!(
            self,
            StoreError::Io {
                kind: io::ErrorKind::NotFound,
                ..
            }
        )
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io { path, kind, source } if *kind == io::ErrorKind::NotFound => {
                write!(
                    f,
                    "{}: not found — run `anago server init` on this machine first ({source})",
                    path.display()
                )
            }
            StoreError::Io { path, kind, source } => {
                f.write_str(&crate::diagnostics::with_target_advice(
                    format!("{}: {source}", path.display()),
                    Some(&crate::diagnostics::Target::system_file(path.clone())),
                    *kind,
                ))
            }
            StoreError::Parse { path, error } => write!(f, "{}: {error}", path.display()),
        }
    }
}

impl std::error::Error for StoreError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU32, Ordering};

    use anago_core::name::DeviceName;
    use anago_core::state::{Peer, PrivateKey, ServerKeys};
    use anago_core::subnet::Subnet;
    use anago_core::token::TokenHash;

    struct TempStore {
        root: PathBuf,
        store: Store,
    }

    impl TempStore {
        fn new() -> TempStore {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("anago-store-{}-{unique}", std::process::id()));
            fs::create_dir_all(&root).expect("temp dir");
            let store = Store::new(&root);
            TempStore { root, store }
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn sample() -> ServerState {
        ServerState {
            domain: "net.example.com".to_string(),
            subnet: Subnet::parse("10.100.0.0/24").unwrap(),
            listen_port: 51820,
            api_port: 443,
            tls_cert_path: "/etc/ssl/anago/fullchain.pem".to_string(),
            tls_key_path: "/etc/ssl/anago/privkey.pem".to_string(),
            server: ServerKeys {
                private_key: PrivateKey::new("c2VydmVyIHByaXZhdGU="),
                public_key: "c2VydmVyIHB1YmxpYw==".to_string(),
                address: "10.100.0.1".parse::<Ipv4Addr>().unwrap(),
            },
            peers: Vec::new(),
            codes: Vec::new(),
        }
    }

    fn peer(name: &str, address: &str) -> Peer {
        Peer {
            name: DeviceName::parse(name).unwrap(),
            public_key: "cGVlciBrZXk=".to_string(),
            address: address.parse().unwrap(),
            token_hash: TokenHash::parse(&"ab".repeat(32)).unwrap(),
            created_at: 1_755_500_000,
            last_seen: None,
        }
    }

    #[test]
    fn a_written_state_reads_back_identical() {
        let temp = TempStore::new();
        let state = sample();
        temp.store.write(&state).unwrap();
        assert_eq!(temp.store.read().unwrap(), state);
    }

    #[test]
    fn the_state_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempStore::new();
        temp.store.write(&sample()).unwrap();
        let mode = fs::metadata(temp.store.paths().state_file())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_missing_state_file_says_to_run_init() {
        let temp = TempStore::new();
        let e = temp.store.read().unwrap_err();
        assert!(e.is_missing());
        assert!(e.to_string().contains("anago server init"), "{e}");
    }

    #[test]
    fn locking_a_machine_that_is_not_a_hub_names_the_state_file() {
        // The lock file is an implementation detail; "you have not run
        // server init" is the answer the operator needs.
        let temp = TempStore::new();
        let missing = Store::new(temp.root.join("not-a-hub"));
        let e = match missing.lock() {
            Err(e) => e,
            Ok(_) => panic!("a directory that does not exist cannot be locked"),
        };
        assert!(e.is_missing());
        assert!(e.to_string().contains("state.json"), "{e}");
        assert!(!e.to_string().contains("state.lock"), "{e}");
        assert!(e.to_string().contains("anago server init"), "{e}");
    }

    #[test]
    fn a_corrupt_state_file_is_reported_with_its_path() {
        let temp = TempStore::new();
        fs::write(temp.store.paths().state_file(), "{not json").unwrap();
        let e = temp.store.read().unwrap_err();
        assert!(!e.is_missing());
        assert!(matches!(e, StoreError::Parse { .. }), "{e:?}");
        assert!(
            e.to_string()
                .starts_with(&temp.store.paths().state_file().display().to_string()),
            "{e}"
        );
    }

    #[test]
    fn changes_land_only_on_commit() {
        let temp = TempStore::new();
        temp.store.write(&sample()).unwrap();

        {
            let mut guard = temp.store.lock().unwrap();
            guard.state_mut().peers.push(peer("macbook", "10.100.0.2"));
            // Dropped without commit: the failure path of a handler.
        }
        assert!(temp.store.read().unwrap().peers.is_empty());

        let mut guard = temp.store.lock().unwrap();
        guard.state_mut().peers.push(peer("macbook", "10.100.0.2"));
        guard.commit().unwrap();
        assert_eq!(temp.store.read().unwrap().peers.len(), 1);
    }

    #[test]
    fn a_second_writer_waits_for_the_first() {
        // Two joins racing must not both read "the lowest free address
        // is .2" (§13).
        let temp = TempStore::new();
        temp.store.write(&sample()).unwrap();

        let guard = temp.store.lock().unwrap();
        let lock_path = temp.store.paths().state_lock();
        assert!(
            FileLock::try_acquire(&lock_path).unwrap().is_none(),
            "the lock should be held"
        );
        drop(guard);
        assert!(FileLock::try_acquire(&lock_path).unwrap().is_some());
    }

    #[test]
    fn reads_do_not_block_on_the_lock() {
        // `ls` and `GET /peers` take a possibly-stale answer over
        // waiting behind a join.
        let temp = TempStore::new();
        temp.store.write(&sample()).unwrap();
        let _guard = temp.store.lock().unwrap();
        assert!(temp.store.read().is_ok());
    }
}
