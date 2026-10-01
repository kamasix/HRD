//! `/etc/cordial-hrd/netd.toml` and the users it refers to.

use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use hrd_core::{Error, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetdConfig {
    /// The unprivileged user whose manager may talk to this helper. Its uid is
    /// the only one (besides root) accepted on the socket, and the socket is
    /// given to its group (the Unix group, not a proxy group).
    pub service_user: String,
    pub service_group: String,
    /// Re-apply the proxy groups recorded by the last `apply` when the helper starts
    /// (after a reboot, `/run` is empty). **Off by default**: a package must not
    /// change the network on its own; the operator turns this on deliberately.
    pub apply_on_start: bool,
    /// Let the service user (and so the web panel) define a proxy, that is hand
    /// the helper a WireGuard file with its private key. **Off by default**:
    /// whoever can define a proxy decides where the traffic of every account
    /// that uses it goes, so out of the box only root may. Switching it on in
    /// this root-owned file is the administrator saying the panel may do it.
    pub allow_service_define: bool,
}

impl Default for NetdConfig {
    fn default() -> Self {
        NetdConfig {
            service_user: "cordial".into(),
            service_group: "cordial".into(),
            apply_on_start: false,
            allow_service_define: false,
        }
    }
}

impl NetdConfig {
    pub fn load(path: &Path) -> Result<NetdConfig> {
        let mut file = match fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(NetdConfig::default()),
            Err(e) => return Err(Error::io(format!("read {}", path.display()), e)),
        };
        // This file decides whether the service user may hand the helper a private
        // key. Whoever can write it can switch that on, so a helper running as
        // root insists on a file that only root can write.
        if rustix::process::geteuid().is_root() {
            let meta = file
                .metadata()
                .map_err(|e| Error::io(format!("stat {}", path.display()), e))?;
            if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return Err(Error::Denied(format!(
                    "{} must be owned by root and writable by no one else: it decides who may define a proxy",
                    path.display()
                )));
            }
        }
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|e| Error::io(format!("read {}", path.display()), e))?;
        toml::from_str(&text).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))
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
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_service_user_may_not_define_a_tunnel_unless_the_file_says_so() {
        assert!(!NetdConfig::default().allow_service_define);
        let c: NetdConfig = toml::from_str("allow_service_define = true\n").unwrap();
        assert!(c.allow_service_define);
        // the shipped example is valid and leaves it off
        let ex: NetdConfig =
            toml::from_str(include_str!("../../../config/netd.toml.example")).unwrap();
        assert!(!ex.allow_service_define);
        // a typo is an error, not a silent default
        assert!(toml::from_str::<NetdConfig>("allow_service_defin = true\n").is_err());
    }

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
    fn a_root_helper_refuses_a_config_file_that_others_can_write_or_do_not_own() {
        if !rustix::process::geteuid().is_root() {
            return; // the check is for the privileged helper; nothing to see as anyone else
        }
        let dir = std::env::temp_dir().join(format!("hrd-netd-cfg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("netd.toml");
        fs::write(&f, "allow_service_define = true\n").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(NetdConfig::load(&f).unwrap().allow_service_define);
        fs::set_permissions(&f, fs::Permissions::from_mode(0o664)).unwrap();
        assert!(matches!(NetdConfig::load(&f), Err(Error::Denied(_))));
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
        rustix::fs::chown(&f, Some(rustix::fs::Uid::from_raw(1)), None).unwrap();
        assert!(matches!(NetdConfig::load(&f), Err(Error::Denied(_))));
        // no file at all is the defaults
        assert!(
            !NetdConfig::load(&dir.join("absent.toml"))
                .unwrap()
                .allow_service_define
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_keys_are_refused() {
        assert!(toml::from_str::<NetdConfig>("apply_on_strat = true").is_err());
        assert!(!NetdConfig::default().apply_on_start);
    }
}
