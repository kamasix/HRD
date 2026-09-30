//! The runtime store: immutable, shared by every client.
//!
//! ```text
//! runtime/
//!   .lock                    flock: one writer at a time
//!   .staging/                private scratch for imports in progress
//!   builds/<engine version>/
//!     manifest.json          provenance and hashes, written once
//!     engine/libroblox.so    (+ .cordial-engine-version)
//!     apk/base.apk           (+ split_config.<abi>.apk when the engine is in a split)
//!     assets/                the APK's assets/ tree, stamped for cordial-run
//!   current  -> builds/<v>   what new clients start on
//!   previous -> builds/<v>   what `current` was before the last switch
//! ```
//!
//! A published build is never modified. Clients get the directory read-only
//! (`0550`/`0440`, owner and group only) and `cordial-run` is pointed at the
//! files inside it, so a hundred clients map one inode and the kernel's page
//! cache holds one copy of the engine's text. Switching `current` changes what
//! the *next* client starts on; a running client keeps the files it started
//! with, which nothing can remove while it is using them because [`Store::remove`]
//! is told which versions are in use.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hrd_core::fsutil::{self, FileLock};
use hrd_core::{Error, Result};
use serde::{Deserialize, Serialize};

pub const SCHEMA: u32 = 1;
/// The upstream commit this project is pinned to; recorded in every manifest so
/// a build's provenance names the loader it was prepared for.
pub const UPSTREAM_COMMIT: &str = "b0ee9f39f03eae61362edc28214bb1533e87d8d0";

pub const FILE_MODE: u32 = 0o440;
pub const DIR_MODE: u32 = 0o550;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileRecord {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveRecord {
    /// `base` (assets and manifest), `engine` (holds libroblox.so), or
    /// `monolithic` (both).
    pub role: String,
    pub stored_as: String,
    /// The name the operator gave it. Provenance only; never a path.
    pub given_as: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetsRecord {
    pub files: u64,
    pub bytes: u64,
    /// SHA-256 over the sorted list of `path NUL size NUL sha256 LF`, so the
    /// whole tree can be re-verified by one comparison.
    pub tree_sha256: String,
    /// The string written to `assets/.from`, which is what `cordial-run` compares
    /// against the `--apk` it is given.
    pub stamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Consistency {
    /// `checked` or `unchecked`.
    pub status: String,
    pub package: Option<String>,
    pub version_code: Option<u32>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildManifest {
    pub schema: u32,
    pub version: String,
    pub abi: String,
    pub imported_at: u64,
    pub tool: String,
    pub upstream_commit: String,
    pub label: Option<String>,
    pub signer_sha256: String,
    pub engine: FileRecord,
    pub archives: Vec<ArchiveRecord>,
    /// Verified, same signer, and not needed (other locale/density splits).
    pub unused: Vec<FileRecord>,
    pub assets: AssetsRecord,
    pub consistency: Consistency,
}

impl BuildManifest {
    pub fn is_split(&self) -> bool {
        self.archives.iter().any(|a| a.role == "engine")
    }
}

#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

/// A version string as the engine reports it: four dot-separated numbers.
pub fn valid_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    v.len() <= 32
        && parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 10 && p.bytes().all(|b| b.is_ascii_digit()))
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Store {
        Store { root: root.into() }
    }

    /// Create the directories with the right modes.
    pub fn ensure(&self) -> Result<()> {
        fsutil::ensure_private_dir(&self.root, 0o750)?;
        fsutil::ensure_private_dir(&self.builds_dir(), 0o750)?;
        fsutil::ensure_private_dir(&self.staging_dir(), 0o700)?;
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn builds_dir(&self) -> PathBuf {
        self.root.join("builds")
    }
    pub fn staging_dir(&self) -> PathBuf {
        self.root.join(".staging")
    }
    pub fn build_dir(&self, version: &str) -> PathBuf {
        self.builds_dir().join(version)
    }
    fn link(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// Take the store lock, waiting up to `timeout`.
    pub fn lock(&self, timeout: Duration) -> Result<FileLock> {
        let path = self.root.join(".lock");
        let start = Instant::now();
        loop {
            if let Some(l) = FileLock::try_acquire(&path)? {
                return Ok(l);
            }
            if start.elapsed() >= timeout {
                return Err(Error::conflict(
                    "another runtime import, switch or removal is in progress",
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    pub fn manifest(&self, version: &str) -> Result<BuildManifest> {
        if !valid_version(version) {
            return Err(Error::invalid(format!(
                "{version:?} is not an engine version (expected four numbers such as 2.738.0.1397)"
            )));
        }
        let path = self.build_dir(version).join("manifest.json");
        let bytes = fsutil::read_limited(&path, 4 * 1024 * 1024).map_err(|e| match e {
            Error::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
                Error::not_found(format!("no runtime {version} is installed"))
            }
            other => other,
        })?;
        serde_json::from_slice(&bytes)
            .map_err(|e| Error::Internal(format!("{}: {e}", path.display())))
    }

    /// All installed builds, newest import first.
    pub fn list(&self) -> Vec<BuildManifest> {
        let mut out: Vec<BuildManifest> = fs::read_dir(self.builds_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|n| valid_version(n))
            .filter_map(|n| self.manifest(&n).ok())
            .collect();
        out.sort_by(|a, b| {
            b.imported_at
                .cmp(&a.imported_at)
                .then(b.version.cmp(&a.version))
        });
        out
    }

    fn read_link_version(&self, name: &str) -> Option<String> {
        let target = fs::read_link(self.link(name)).ok()?;
        let v = target.file_name()?.to_str()?.to_string();
        (valid_version(&v) && self.build_dir(&v).is_dir()).then_some(v)
    }

    pub fn current(&self) -> Option<String> {
        self.read_link_version("current")
    }

    pub fn previous(&self) -> Option<String> {
        self.read_link_version("previous")
    }

    fn set_link(&self, name: &str, version: &str) -> Result<()> {
        let tmp = self
            .root
            .join(format!(".{name}.tmp.{}", std::process::id()));
        let _ = fs::remove_file(&tmp);
        std::os::unix::fs::symlink(Path::new("builds").join(version), &tmp)
            .map_err(|e| Error::io("create link", e))?;
        fs::rename(&tmp, self.link(name)).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            Error::io(format!("replace {name}"), e)
        })
    }

    /// Make `version` what new clients start on, remembering the old one as
    /// `previous`. The caller holds the store lock.
    pub fn use_version(&self, version: &str) -> Result<()> {
        self.manifest(version)?;
        let old = self.current();
        if old.as_deref() == Some(version) {
            return Ok(());
        }
        if let Some(old) = old {
            self.set_link("previous", &old)?;
        }
        self.set_link("current", version)?;
        File::open(&self.root)
            .and_then(|d| d.sync_all())
            .map_err(|e| Error::io("sync store", e))?;
        Ok(())
    }

    /// Delete a build. Refuses `current`, `previous` and anything in `in_use`.
    pub fn remove(&self, version: &str, in_use: &[String]) -> Result<()> {
        self.manifest(version)?;
        if self.current().as_deref() == Some(version) {
            return Err(Error::conflict(format!(
                "{version} is the current runtime; switch to another first"
            )));
        }
        if self.previous().as_deref() == Some(version) {
            return Err(Error::conflict(format!("{version} is the previous runtime, kept so you can go back; switch `previous` first")));
        }
        if in_use.iter().any(|v| v == version) {
            return Err(Error::conflict(format!(
                "{version} is in use by a running instance"
            )));
        }
        let dir = self.build_dir(version);
        make_writable(&dir)?;
        // Out of the way first, so a crash mid-delete leaves no half-tree under
        // a valid-looking name.
        let gone = self
            .staging_dir()
            .join(format!("removing-{version}-{}", std::process::id()));
        fs::rename(&dir, &gone)
            .map_err(|e| Error::io(format!("move {} aside", dir.display()), e))?;
        fsutil::remove_dir_all_if_exists(&gone)
    }
}

use std::fs::File;

/// Give the owner write permission throughout a tree, so it can be deleted.
/// Does not follow symlinks.
pub fn make_writable(path: &Path) -> Result<()> {
    let md =
        fs::symlink_metadata(path).map_err(|e| Error::io(format!("stat {}", path.display()), e))?;
    if md.file_type().is_symlink() {
        return Ok(());
    }
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(md.permissions().mode() | 0o700),
    )
    .map_err(|e| Error::io(format!("chmod {}", path.display()), e))?;
    if md.is_dir() {
        for e in fs::read_dir(path)
            .map_err(|e| Error::io(format!("read {}", path.display()), e))?
            .flatten()
        {
            make_writable(&e.path())?;
        }
    }
    Ok(())
}

/// Seal a tree: files `0440`, directories `0550`. Does not follow symlinks
/// (there are none in a build, and a stray one is left alone rather than
/// chmod'ed through).
pub fn seal(path: &Path) -> Result<()> {
    let md =
        fs::symlink_metadata(path).map_err(|e| Error::io(format!("stat {}", path.display()), e))?;
    if md.file_type().is_symlink() {
        return Err(Error::Internal(format!(
            "{} is a symbolic link inside a build",
            path.display()
        )));
    }
    if md.is_dir() {
        for e in fs::read_dir(path)
            .map_err(|e| Error::io(format!("read {}", path.display()), e))?
            .flatten()
        {
            seal(&e.path())?;
        }
        fs::set_permissions(path, fs::Permissions::from_mode(DIR_MODE))
            .map_err(|e| Error::io(format!("chmod {}", path.display()), e))
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE))
            .map_err(|e| Error::io(format!("chmod {}", path.display()), e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(tag: &str) -> Store {
        let d = std::env::temp_dir().join(format!("hrd-store-{tag}-{}", std::process::id()));
        let _ = make_writable(&d);
        let _ = fs::remove_dir_all(&d);
        let s = Store::new(d);
        s.ensure().unwrap();
        s
    }

    fn fake_build(s: &Store, version: &str, at: u64) {
        let d = s.build_dir(version);
        fs::create_dir_all(d.join("engine")).unwrap();
        let m = BuildManifest {
            schema: SCHEMA,
            version: version.into(),
            abi: "x86_64".into(),
            imported_at: at,
            tool: "test".into(),
            upstream_commit: UPSTREAM_COMMIT.into(),
            label: None,
            signer_sha256: "ab".repeat(32),
            engine: FileRecord {
                path: "engine/libroblox.so".into(),
                size: 1,
                sha256: "cd".repeat(32),
            },
            archives: vec![],
            unused: vec![],
            assets: AssetsRecord {
                files: 0,
                bytes: 0,
                tree_sha256: String::new(),
                stamp: String::new(),
            },
            consistency: Consistency::default(),
        };
        fsutil::write_json_atomic(&d.join("manifest.json"), &m, 0o440).unwrap();
        fs::write(d.join("engine/libroblox.so"), b"x").unwrap();
        seal(&d).unwrap();
    }

    #[test]
    fn version_strings_are_the_engines_shape_and_nothing_else() {
        for ok in ["2.738.0.1397", "2.1.0.1", "10.20.30.40"] {
            assert!(valid_version(ok), "{ok}");
        }
        for bad in [
            "",
            "2.738.0",
            "2.738.0.1397.1",
            "a.b.c.d",
            "2..0.1",
            "../../etc",
            "2.738.0.1397/x",
            "2.738.0.13 97",
            &"1.".repeat(20),
        ] {
            assert!(!valid_version(bad), "{bad:?}");
        }
    }

    #[test]
    fn use_switches_current_and_remembers_previous() {
        let s = store("use");
        fake_build(&s, "2.738.0.1397", 10);
        fake_build(&s, "2.739.0.1400", 20);
        let _l = s.lock(Duration::from_secs(1)).unwrap();
        assert_eq!(s.current(), None);
        s.use_version("2.738.0.1397").unwrap();
        assert_eq!(s.current().as_deref(), Some("2.738.0.1397"));
        assert_eq!(s.previous(), None);
        s.use_version("2.739.0.1400").unwrap();
        assert_eq!(s.current().as_deref(), Some("2.739.0.1400"));
        assert_eq!(s.previous().as_deref(), Some("2.738.0.1397"));
        // back
        s.use_version("2.738.0.1397").unwrap();
        assert_eq!(s.previous().as_deref(), Some("2.739.0.1400"));
        assert!(s.use_version("2.000.0.1").is_err());
        let names: Vec<_> = s.list().into_iter().map(|m| m.version).collect();
        assert_eq!(
            names,
            ["2.739.0.1400", "2.738.0.1397"],
            "newest import first"
        );
    }

    #[test]
    fn remove_refuses_current_previous_and_in_use_and_can_delete_a_sealed_tree() {
        let s = store("rm");
        for (v, t) in [
            ("2.1.0.1", 1),
            ("2.2.0.1", 2),
            ("2.3.0.1", 3),
            ("2.4.0.1", 4),
        ] {
            fake_build(&s, v, t);
        }
        s.use_version("2.1.0.1").unwrap();
        s.use_version("2.2.0.1").unwrap();
        assert!(s.remove("2.2.0.1", &[]).is_err(), "current");
        assert!(s.remove("2.1.0.1", &[]).is_err(), "previous");
        assert!(s.remove("2.3.0.1", &["2.3.0.1".into()]).is_err(), "in use");
        s.remove("2.3.0.1", &["2.4.0.1".into()]).unwrap();
        assert!(!s.build_dir("2.3.0.1").exists());
        assert!(s.manifest("2.3.0.1").is_err());
        assert!(s.list().iter().all(|m| m.version != "2.3.0.1"));
    }

    #[test]
    fn a_sealed_build_cannot_be_written_by_its_owner_without_a_deliberate_chmod() {
        let s = store("seal");
        fake_build(&s, "2.9.0.1", 1);
        let f = s.build_dir("2.9.0.1").join("engine/libroblox.so");
        assert_eq!(
            fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            FILE_MODE
        );
        assert_eq!(
            fs::metadata(s.build_dir("2.9.0.1"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            DIR_MODE
        );
        // root ignores mode bits, so only assert the observable bits above
    }

    #[test]
    fn the_lock_excludes_a_second_writer() {
        let s = store("lock");
        let _a = s.lock(Duration::from_secs(1)).unwrap();
        assert!(s.lock(Duration::from_millis(300)).is_err());
    }
}
