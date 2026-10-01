//! The installed runtime, as the daemon needs to see it.
//!
//! Installing, switching and removing builds is `hrd-import`'s job and is
//! done by running it; the daemon only reads which build is current and runs the
//! importer with the operator's files.

use std::path::PathBuf;

use hrd_core::layout::Layout;
use hrd_core::{Error, Result};

#[derive(Debug, Clone)]
pub struct Build {
    pub version: String,
    pub dir: PathBuf,
}

fn valid_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
        && !v.starts_with('.')
}

/// The build new runs use: the `current` link, read, not followed blindly.
pub fn current(layout: &Layout) -> Result<Build> {
    let store = layout.runtime_store();
    let link = store.join("current");
    let target = std::fs::read_link(&link).map_err(|_| {
        Error::unavailable(
            "no runtime is installed: import a Roblox Android build first (`hrdctl runtime import --apk PATH`)",
        )
    })?;
    let version = target
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .filter(|v| valid_version(v))
        .ok_or_else(|| Error::invalid(format!("{} points somewhere unexpected", link.display())))?;
    let dir = store.join("builds").join(&version);
    if !dir.join("engine/libroblox.so").is_file()
        || !dir.join("apk/base.apk").is_file()
        || !dir.join("assets").is_dir()
    {
        return Err(Error::invalid(format!(
            "build {version} is incomplete ({} lacks engine, apk or assets); run `hrd-import verify`",
            dir.display()
        )));
    }
    Ok(Build { version, dir })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_store_says_what_to_do() {
        let l = Layout::under(std::path::Path::new("/nonexistent-hrd"));
        let e = current(&l).unwrap_err().to_string();
        assert!(e.contains("runtime import"), "{e}");
    }

    #[test]
    fn current_reads_the_link_and_checks_the_layout() {
        let d = std::env::temp_dir().join(format!("hrd-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let l = Layout::under(&d);
        let store = l.runtime_store();
        let b = store.join("builds/2.1.0");
        std::fs::create_dir_all(b.join("engine")).unwrap();
        std::fs::create_dir_all(b.join("apk")).unwrap();
        std::fs::create_dir_all(b.join("assets")).unwrap();
        std::os::unix::fs::symlink("builds/2.1.0", store.join("current")).unwrap();
        assert!(current(&l).is_err(), "engine and apk files are missing");
        std::fs::write(b.join("engine/libroblox.so"), b"x").unwrap();
        std::fs::write(b.join("apk/base.apk"), b"x").unwrap();
        let c = current(&l).unwrap();
        assert_eq!(c.version, "2.1.0");
        std::fs::remove_file(store.join("current")).unwrap();
        std::os::unix::fs::symlink("../../../etc", store.join("current")).unwrap();
        assert!(
            current(&l).is_err(),
            "a link that leaves the store is not a build"
        );
        std::fs::remove_dir_all(d).ok();
    }
}
