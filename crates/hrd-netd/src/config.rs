//! `/etc/cordial-hrd/netd.toml` and the users it refers to.

use std::fs;
use std::path::Path;

use hrd_core::{Error, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetdConfig {
    /// The unprivileged user whose manager may talk to this helper. Its uid is
    /// the only one (besides root) accepted on the socket, and the socket is
    /// given to its group.
    pub service_user: String,
    pub service_group: String,
    /// Re-apply the groups recorded by the last `apply` when the helper starts
    /// (after a reboot, `/run` is empty). **Off by default**: a package must not
    /// change the network on its own; the operator turns this on deliberately.
    pub apply_on_start: bool,
}

impl Default for NetdConfig {
    fn default() -> Self {
        NetdConfig {
            service_user: "cordial".into(),
            service_group: "cordial".into(),
            apply_on_start: false,
        }
    }
}

impl NetdConfig {
    pub fn load(path: &Path) -> Result<NetdConfig> {
        match fs::read_to_string(path) {
            Ok(t) => {
                toml::from_str(&t).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(NetdConfig::default()),
            Err(e) => Err(Error::io(format!("read {}", path.display()), e)),
        }
    }
}

/// `(uid, gid)` of `name` from `passwd_text` (the format of `/etc/passwd`).
pub fn lookup_user(passwd_text: &str, name: &str) -> Option<(u32, u32)> {
    passwd_text.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == name).then(|| {
            let _pw = f.next();
            Some((f.next()?.parse().ok()?, f.next()?.parse().ok()?))
        })?
    })
}

pub fn lookup_group(group_text: &str, name: &str) -> Option<u32> {
    group_text.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == name).then(|| {
            let _pw = f.next();
            f.next()?.parse().ok()
        })?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users_and_groups_are_looked_up_by_exact_name() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\ncordial:x:998:997::/var/lib/cordial-hrd:/usr/sbin/nologin\ncordial2:x:999:999::/:/bin/false\n";
        assert_eq!(lookup_user(passwd, "cordial"), Some((998, 997)));
        assert_eq!(lookup_user(passwd, "cordia"), None);
        assert_eq!(lookup_user(passwd, "nobody"), None);
        let group = "root:x:0:\ncordial:x:997:alice,bob\n";
        assert_eq!(lookup_group(group, "cordial"), Some(997));
        assert_eq!(lookup_group(group, "cord"), None);
    }

    #[test]
    fn unknown_keys_are_refused() {
        assert!(toml::from_str::<NetdConfig>("apply_on_strat = true").is_err());
        assert!(!NetdConfig::default().apply_on_start);
    }
}
