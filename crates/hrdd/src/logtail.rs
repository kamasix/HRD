//! Following a growing log file from where we stopped.
//!
//! The same shape as upstream's own watcher: remember an offset, notice when
//! the file got shorter (rotation, a new file under the same name) and start
//! again, hold a partial last line until its newline arrives. Reads are capped
//! per poll so a chatty engine cannot stall the supervisor; if more than the
//! cap is waiting, the oldest part is skipped and counted.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const MAX_LINE_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub struct Tail {
    path: PathBuf,
    offset: u64,
    inode: Option<u64>,
    /// First bytes of the file as first read. An inode number can be reused by
    /// a replacement file, so identity is also checked by content.
    head: Vec<u8>,
    partial: Vec<u8>,
    pub skipped_bytes: u64,
}

impl Tail {
    pub fn new(path: impl Into<PathBuf>) -> Tail {
        Tail {
            path: path.into(),
            offset: 0,
            inode: None,
            head: Vec::new(),
            partial: Vec::new(),
            skipped_bytes: 0,
        }
    }

    /// Start at the current end: only lines written from now on.
    pub fn from_end(path: impl Into<PathBuf>) -> Tail {
        let mut t = Tail::new(path);
        if let Ok(md) = std::fs::metadata(&t.path) {
            t.offset = md.len();
            t.inode = Some(md.ino());
        }
        t
    }

    /// Start reading at byte `offset`.
    pub fn from_offset(path: impl Into<PathBuf>, offset: u64) -> Tail {
        let mut t = Tail::new(path);
        t.offset = offset;
        t
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn set_path(&mut self, p: PathBuf) {
        if p != self.path {
            self.path = p;
            self.offset = 0;
            self.inode = None;
            self.head.clear();
            self.partial.clear();
        }
    }

    /// New complete lines, at most `max_bytes` worth of file read.
    pub fn poll(&mut self, max_bytes: u64) -> Vec<String> {
        let Ok(mut f) = File::open(&self.path) else {
            return Vec::new();
        };
        let Ok(md) = f.metadata() else {
            return Vec::new();
        };
        let mut head = [0u8; 32];
        let hn = f.read(&mut head).unwrap_or(0);
        let head = &head[..hn];
        let same_head =
            self.head.is_empty() || head.starts_with(&self.head) || self.head.starts_with(head);
        if self.inode.is_some_and(|i| i != md.ino()) || md.len() < self.offset || !same_head {
            self.offset = 0;
            self.partial.clear();
            self.head.clear();
        }
        if self.head.len() < head.len() {
            self.head = head.to_vec();
        }
        self.inode = Some(md.ino());
        if md.len() == self.offset {
            return Vec::new();
        }
        let mut start = self.offset;
        if md.len() - start > max_bytes {
            let skip = md.len() - max_bytes - start;
            self.skipped_bytes += skip;
            start += skip;
            self.partial.clear();
        }
        if f.seek(SeekFrom::Start(start)).is_err() {
            return Vec::new();
        }
        let mut buf = vec![0u8; (md.len() - start) as usize];
        let n = f.read(&mut buf).unwrap_or(0);
        buf.truncate(n);
        self.offset = start + n as u64;
        let mut out = Vec::new();
        for b in buf {
            if b == b'\n' {
                out.push(
                    String::from_utf8_lossy(&self.partial)
                        .trim_end_matches('\r')
                        .to_string(),
                );
                self.partial.clear();
            } else if self.partial.len() < MAX_LINE_BYTES {
                self.partial.push(b);
            }
        }
        out
    }
}

/// Byte offset of the start of the last line that begins with `prefix`, looking
/// only at the final `window` bytes of the file.
pub fn offset_of_last_line(path: &Path, prefix: &str, window: u64) -> Option<u64> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let start = len.saturating_sub(window);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::new();
    f.take(window).read_to_end(&mut buf).ok()?;
    let mut found = None;
    let mut pos = 0usize;
    for line in buf.split(|b| *b == b'\n') {
        // A line cut by the window's start is not a line start.
        let is_start = pos > 0 || start == 0;
        if is_start && line.starts_with(prefix.as_bytes()) {
            found = Some(start + pos as u64);
        }
        pos += line.len() + 1;
    }
    found
}

/// The last `n` lines of a file, reading at most `window` bytes from its end.
pub fn last_lines(path: &Path, n: usize, window: u64) -> Vec<String> {
    let Ok(mut f) = File::open(path) else {
        return Vec::new();
    };
    let Ok(md) = f.metadata() else {
        return Vec::new();
    };
    let start = md.len().saturating_sub(window);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    let _ = f.take(window).read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<&str> = text.lines().collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0); // probably cut mid-line
    }
    let from = lines.len().saturating_sub(n);
    lines[from..].iter().map(|l| l.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hrd-tail-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn lines_arrive_once_and_partial_lines_wait() {
        let d = scratch("a");
        let p = d.join("log");
        let mut t = Tail::new(&p);
        assert!(t.poll(1 << 20).is_empty(), "no file yet");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"one\ntwo\nthr").unwrap();
        assert_eq!(t.poll(1 << 20), vec!["one", "two"]);
        f.write_all(b"ee\n").unwrap();
        assert_eq!(t.poll(1 << 20), vec!["three"]);
        assert!(t.poll(1 << 20).is_empty());
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn truncation_and_replacement_restart_from_the_top() {
        let d = scratch("b");
        let p = d.join("log");
        std::fs::write(&p, b"aaaaaaaa\nbbbbbbbb\n").unwrap();
        let mut t = Tail::new(&p);
        assert_eq!(t.poll(1 << 20).len(), 2);
        std::fs::write(&p, b"c\n").unwrap();
        assert_eq!(t.poll(1 << 20), vec!["c"]);
        std::fs::remove_file(&p).unwrap();
        std::fs::write(&p, b"dddddddddddddddd\n").unwrap();
        assert_eq!(t.poll(1 << 20), vec!["dddddddddddddddd"]);
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn a_flood_is_capped_and_counted() {
        let d = scratch("c");
        let p = d.join("log");
        let mut data = String::new();
        for i in 0..1000 {
            data.push_str(&format!("line {i}\n"));
        }
        std::fs::write(&p, &data).unwrap();
        let mut t = Tail::new(&p);
        let got = t.poll(200);
        assert!(got.len() < 40 && !got.is_empty());
        assert!(t.skipped_bytes > 0);
        assert_eq!(got.last().unwrap(), "line 999");
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn the_last_banner_is_found_by_offset() {
        let d = scratch("e");
        let p = d.join("log");
        std::fs::write(&p, b"=== run 1\nold\n=== run 2\nnew\n").unwrap();
        let off = offset_of_last_line(&p, "=== run", 1 << 16).unwrap();
        assert_eq!(off, 14);
        let mut t = Tail::from_offset(&p, off);
        assert_eq!(t.poll(1000), vec!["=== run 2", "new"]);
        assert_eq!(offset_of_last_line(&p, "=== nope", 1 << 16), None);
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn from_end_ignores_history_and_last_lines_reads_the_tail() {
        let d = scratch("d");
        let p = d.join("log");
        std::fs::write(&p, b"old\nolder\n").unwrap();
        let mut t = Tail::from_end(&p);
        assert!(t.poll(100).is_empty());
        std::fs::OpenOptions::new()
            .append(true)
            .open(&p)
            .unwrap()
            .write_all(b"new\n")
            .unwrap();
        assert_eq!(t.poll(100), vec!["new"]);
        assert_eq!(last_lines(&p, 2, 1 << 16), vec!["older", "new"]);
        std::fs::remove_dir_all(d).ok();
    }
}
