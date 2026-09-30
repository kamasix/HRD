//! Copying an input into the staging area.
//!
//! Everything the importer does afterwards, inspecting, verifying, extracting,
//! reads the staged copy and never the operator's file. That closes the window
//! upstream leaves between "verified this path" and "extracted from that path":
//! there is no path left for anyone to swap.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;

use hrd_core::{Error, Result};
use rustix::fs::OFlags;
use sha2::{Digest, Sha256};

/// Largest input accepted. The monolithic Roblox build is about 230 MB; this
/// leaves room for growth without letting `/dev/zero`-shaped inputs fill a disk.
pub const MAX_INPUT: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    pub size: u64,
    pub sha256: String,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Copy `src` to `dest` (created exclusively, mode 0600), hashing as it goes.
///
/// `src` must be a regular file. Anything else, a pipe that never ends, a
/// device, a directory, is refused before a byte is read.
pub fn copy_hashing(src: &mut File, dest: &Path, max: u64) -> Result<Staged> {
    let md = src.metadata().map_err(|e| Error::io("stat input", e))?;
    if !md.file_type().is_file() {
        let kind = if md.file_type().is_dir() {
            "a directory"
        } else if md.file_type().is_fifo() {
            "a pipe"
        } else if md.file_type().is_char_device() || md.file_type().is_block_device() {
            "a device"
        } else {
            "not a regular file"
        };
        return Err(Error::invalid(format!(
            "input is {kind}; only regular files are imported"
        )));
    }
    if md.len() > max {
        return Err(Error::invalid(format!(
            "input is {} bytes, more than the {max} byte limit",
            md.len()
        )));
    }
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open(dest)
        .map_err(|e| Error::io(format!("create {}", dest.display()), e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = src.read(&mut buf).map_err(|e| Error::io("read input", e))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        // The file may grow while it is read; the limit is on what is copied,
        // not on what `stat` said.
        if total > max {
            return Err(Error::invalid(format!(
                "input grew past the {max} byte limit while it was read"
            )));
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])
            .map_err(|e| Error::io(format!("write {}", dest.display()), e))?;
    }
    out.sync_all()
        .map_err(|e| Error::io(format!("sync {}", dest.display()), e))?;
    Ok(Staged {
        size: total,
        sha256: hex(&hasher.finalize()),
    })
}

/// SHA-256 of a file, streaming.
pub fn hash_file(path: &Path) -> Result<Staged> {
    let mut f = File::open(path).map_err(|e| Error::io(format!("open {}", path.display()), e))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| Error::io(format!("read {}", path.display()), e))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        h.update(&buf[..n]);
    }
    Ok(Staged {
        size: total,
        sha256: hex(&h.finalize()),
    })
}

/// Free bytes on the filesystem holding `path`.
pub fn free_bytes(path: &Path) -> Result<u64> {
    let st = rustix::fs::statvfs(path).map_err(|e| {
        Error::io(
            format!("statvfs {}", path.display()),
            std::io::Error::from_raw_os_error(e.raw_os_error()),
        )
    })?;
    Ok(st.f_bavail.saturating_mul(st.f_frsize))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("hrd-stage-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn copies_and_hashes() {
        let d = scratch("ok");
        std::fs::write(d.join("in"), b"abc").unwrap();
        let mut f = File::open(d.join("in")).unwrap();
        let s = copy_hashing(&mut f, &d.join("out"), 1000).unwrap();
        assert_eq!(s.size, 3);
        assert_eq!(
            s.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(std::fs::read(d.join("out")).unwrap(), b"abc");
        assert_eq!(hash_file(&d.join("out")).unwrap(), s);
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn refuses_oversize_directories_and_devices() {
        let d = scratch("refuse");
        std::fs::write(d.join("big"), vec![0u8; 100]).unwrap();
        let mut f = File::open(d.join("big")).unwrap();
        assert!(copy_hashing(&mut f, &d.join("o1"), 99).is_err());
        let mut dir = File::open(&d).unwrap();
        assert!(copy_hashing(&mut dir, &d.join("o2"), 1000).is_err());
        let mut dev = File::open("/dev/zero").unwrap();
        let e = copy_hashing(&mut dev, &d.join("o3"), 1000)
            .unwrap_err()
            .to_string();
        assert!(e.contains("device"), "{e}");
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn will_not_overwrite_or_follow_an_existing_destination() {
        let d = scratch("excl");
        std::fs::write(d.join("in"), b"x").unwrap();
        std::fs::write(d.join("victim"), b"keep").unwrap();
        std::os::unix::fs::symlink(d.join("victim"), d.join("out")).unwrap();
        let mut f = File::open(d.join("in")).unwrap();
        assert!(copy_hashing(&mut f, &d.join("out"), 10).is_err());
        assert_eq!(std::fs::read(d.join("victim")).unwrap(), b"keep");
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn free_space_is_reported() {
        assert!(free_bytes(&std::env::temp_dir()).unwrap() > 0);
    }
}
