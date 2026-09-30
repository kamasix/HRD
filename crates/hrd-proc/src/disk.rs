//! Disk usage of a directory tree, bounded.
//!
//! `cordialctl stats` reports how much disk the caches and the runtime store
//! take. Walking 300 accounts' trees on every call would be its own cost, so
//! the walk is capped by entry count and says when it stopped early.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// Bytes actually allocated (`st_blocks * 512`), counting a hard-linked
    /// file once. This is what `du` reports and what frees up on deletion.
    pub allocated: u64,
    /// Sum of file sizes, counting a hard-linked file once.
    pub apparent: u64,
    pub files: u64,
    /// The walk hit `max_entries` and the figures are a lower bound.
    pub truncated: bool,
}

/// Sum the files under `root` without following symlinks.
pub fn usage(root: &Path, max_entries: u64) -> Usage {
    let mut u = Usage::default();
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let mut stack = vec![root.to_path_buf()];
    let mut entries = 0u64;
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            entries += 1;
            if entries > max_entries {
                u.truncated = true;
                return u;
            }
            let Ok(md) = fs::symlink_metadata(e.path()) else { continue };
            let ft = md.file_type();
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() {
                if md.nlink() > 1 && !seen.insert((md.dev(), md.ino())) {
                    continue;
                }
                u.allocated += md.blocks() * 512;
                u.apparent += md.len();
                u.files += 1;
            }
        }
    }
    u
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_files_once_and_ignores_symlinks() {
        let d = std::env::temp_dir().join(format!("hrd-disk-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("sub")).unwrap();
        fs::write(d.join("a"), vec![1u8; 10_000]).unwrap();
        fs::hard_link(d.join("a"), d.join("sub/a-link")).unwrap();
        std::os::unix::fs::symlink(d.join("a"), d.join("sym")).unwrap();
        fs::write(d.join("sub/b"), vec![2u8; 500]).unwrap();
        let u = usage(&d, 1000);
        assert_eq!(u.files, 2);
        assert_eq!(u.apparent, 10_500);
        assert!(u.allocated >= 10_500);
        assert!(!u.truncated);
        let t = usage(&d, 1);
        assert!(t.truncated);
        fs::remove_dir_all(d).unwrap();
    }
}
