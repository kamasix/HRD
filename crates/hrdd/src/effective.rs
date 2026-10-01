//! The configuration the daemon runs with: the file an administrator edits
//! (`/etc/cordial-hrd/hrdd.toml`, root-owned) overlaid with the settings
//! changed through `config set` or the panel, which are kept in the service
//! user's own state directory (`config-overrides.json`). The file is never
//! modified by the daemon; removing an override returns the key to it.

use std::path::PathBuf;

use serde_json::{Map, Value};

use hrd_core::config::Config;
use hrd_core::layout::Layout;
use hrd_core::{fsutil, Error, Result};

pub fn overrides_file(l: &Layout) -> PathBuf {
    l.state_dir.join("config-overrides.json")
}

pub fn load_overrides(l: &Layout) -> Result<Value> {
    match fsutil::read_limited_opt(&overrides_file(l), 1024 * 1024)? {
        None => Ok(Value::Object(Map::new())),
        Some(b) => {
            let v: Value = serde_json::from_slice(&b)
                .map_err(|e| Error::invalid(format!("{}: {e}", overrides_file(l).display())))?;
            if v.is_object() {
                Ok(v)
            } else {
                Err(Error::invalid(format!(
                    "{} must hold a JSON object",
                    overrides_file(l).display()
                )))
            }
        }
    }
}

fn base_value(l: &Layout) -> Result<Value> {
    match fsutil::read_limited_opt(&l.config_file(), 256 * 1024)? {
        None => Ok(Value::Object(Map::new())),
        Some(b) => {
            let text = std::str::from_utf8(&b)
                .map_err(|_| Error::invalid("the configuration file is not UTF-8"))?;
            let t: toml::Value = toml::from_str(text)
                .map_err(|e| Error::invalid(format!("{}: {e}", l.config_file().display())))?;
            serde_json::to_value(t).map_err(|e| Error::Internal(e.to_string()))
        }
    }
}

pub fn merge(base: &mut Value, over: &Value) {
    match (base, over) {
        (Value::Object(b), Value::Object(o)) => {
            for (k, v) in o {
                merge(b.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (b, o) => *b = o.clone(),
    }
}

pub fn build(base: Value, over: &Value) -> Result<Config> {
    let mut v = base;
    merge(&mut v, over);
    let mut cfg: Config = serde_json::from_value(v)
        .map_err(|e| Error::invalid(format!("invalid configuration: {e}")))?;
    cfg.upgrade_legacy_paths();
    cfg.validate()?;
    Ok(cfg)
}

pub fn load(l: &Layout) -> Result<(Config, Value)> {
    let mut over = load_overrides(l)?;
    for k in strip_protected(&mut over) {
        eprintln!(
            "<4>hrdd: ignoring {k} in config-overrides.json: it can only be set in {}",
            l.config_file().display()
        );
    }
    let base = base_value(l)?;
    match build(base.clone(), &over) {
        Ok(c) => Ok((c, over)),
        Err(e) if over.as_object().is_some_and(|o| !o.is_empty()) => {
            // A bad overrides file must not keep the daemon down (systemd would
            // restart-loop while clients run unsupervised). Set it aside, say
            // so, and start from the administrator's file alone.
            let bad = overrides_file(l).with_extension("json.rejected");
            let _ = std::fs::rename(overrides_file(l), &bad);
            eprintln!(
                "<3>hrdd: config-overrides.json is not valid ({e}); moved to {} and ignored",
                bad.display()
            );
            let empty = Value::Object(Map::new());
            Ok((build(base, &empty)?, empty))
        }
        Err(e) => Err(e),
    }
}

/// Settings that widen who may operate the daemon, which programs it runs, or
/// whether traffic may leave unrouted. The overrides file lives in the service
/// user's own state directory, so anything that user (and therefore any client)
/// can write there must not be able to set these: they are changed in the
/// root-owned configuration file only.
pub fn is_protected(key: &str) -> bool {
    let (sec, name) = key.split_once('.').unwrap_or((key, ""));
    matches!(sec, "service" | "control" | "secrets")
        || (sec == "engine"
            && matches!(
                name,
                "cordial_run" | "enter" | "importer" | "vulkan_icd" | "env" | "compositor"
            ))
        || (sec == "network" && name == "allow_unrouted")
        || (sec == "login" && matches!(name, "console" | "max_text_len"))
}

/// Drop protected keys from an overrides object, returning what was dropped.
fn strip_protected(over: &mut Value) -> Vec<String> {
    let mut dropped = Vec::new();
    if let Some(top) = over.as_object_mut() {
        let secs: Vec<String> = top.keys().cloned().collect();
        for sec in secs {
            let Some(inner) = top.get_mut(&sec).and_then(|v| v.as_object_mut()) else {
                continue;
            };
            let names: Vec<String> = inner.keys().cloned().collect();
            for n in names {
                let k = format!("{sec}.{n}");
                if is_protected(&k) {
                    inner.remove(&n);
                    dropped.push(k);
                }
            }
        }
        top.retain(|_, v| v.as_object().is_none_or(|o| !o.is_empty()));
    }
    dropped
}

/// Set (`Some`) or remove (`None`) a dotted key in an overrides object.
pub fn apply_change(over: &mut Value, key: &str, value: Option<Value>) -> Result<()> {
    let parts: Vec<&str> = key.split('.').collect();
    if parts.len() != 2
        || parts.iter().any(|p| {
            p.is_empty()
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
    {
        return Err(Error::invalid(format!("{key:?} is not a setting name (expected section.name, for example scheduler.max_instances)")));
    }
    if is_protected(key) {
        return Err(Error::Denied(format!(
            "{key} can only be changed in the root-owned configuration file (it decides who may operate the daemon, which programs run, or how traffic is routed)"
        )));
    }
    let obj = over
        .as_object_mut()
        .ok_or_else(|| Error::Internal("overrides is not an object".into()))?;
    match value {
        Some(v) => {
            obj.entry(parts[0])
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .ok_or_else(|| Error::invalid(format!("{} is not a section", parts[0])))?
                .insert(parts[1].to_string(), v);
        }
        None => {
            if let Some(sec) = obj.get_mut(parts[0]).and_then(|s| s.as_object_mut()) {
                sec.remove(parts[1]);
                if sec.is_empty() {
                    obj.remove(parts[0]);
                }
            }
        }
    }
    Ok(())
}

pub enum Effect {
    Live,
    NextStart,
    Restart,
}

/// Sections whose changes are applied to the running daemon.
pub fn is_live_section(sec: &str) -> bool {
    matches!(
        sec,
        "scheduler" | "stats" | "network" | "logs" | "login" | "resources" | "engine" | "runtime"
    )
}

/// When a change to `key` takes hold.
pub fn effect_of(key: &str) -> Effect {
    match key.split('.').next().unwrap_or("") {
        "scheduler" | "stats" | "network" | "logs" | "login" | "runtime" => Effect::Live,
        "resources" | "engine" => Effect::NextStart,
        _ => Effect::Restart,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn overrides_sit_on_top_of_the_file_and_are_validated_as_a_whole() {
        let base = json!({"scheduler": {"max_instances": 50}});
        let c = build(
            base.clone(),
            &json!({"scheduler": {"max_concurrent_starts": 3}}),
        )
        .unwrap();
        assert_eq!(
            (c.scheduler.max_instances, c.scheduler.max_concurrent_starts),
            (50, 3)
        );
        assert!(build(
            base.clone(),
            &json!({"scheduler": {"max_concurrent_starts": 9999}})
        )
        .is_err());
        assert!(
            build(base, &json!({"scheduler": {"no_such_key": 1}})).is_err(),
            "unknown keys stay errors"
        );
    }

    #[test]
    fn protected_keys_cannot_be_set_or_loaded_from_overrides() {
        let mut o = json!({});
        for k in [
            "control.allowed_uids",
            "engine.cordial_run",
            "network.allow_unrouted",
            "secrets.backend",
        ] {
            assert!(apply_change(&mut o, k, Some(json!(1))).is_err(), "{k}");
        }
        let mut o = json!({"control": {"allowed_uids": [5]}, "scheduler": {"max_instances": 3}});
        assert_eq!(strip_protected(&mut o), vec!["control.allowed_uids"]);
        assert_eq!(o, json!({"scheduler": {"max_instances": 3}}));
    }

    #[test]
    fn keys_are_dotted_names_and_removal_tidies_up() {
        let mut o = json!({});
        apply_change(&mut o, "scheduler.max_instances", Some(json!(10))).unwrap();
        assert_eq!(o, json!({"scheduler": {"max_instances": 10}}));
        apply_change(&mut o, "scheduler.max_instances", None).unwrap();
        assert_eq!(o, json!({}));
        for bad in [
            "",
            "scheduler",
            "a.b.c",
            "Scheduler.x",
            "scheduler.",
            "../x.y",
        ] {
            assert!(apply_change(&mut o, bad, Some(json!(1))).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_effect_of_a_change_is_stated_honestly() {
        assert!(matches!(effect_of("scheduler.max_instances"), Effect::Live));
        assert!(matches!(effect_of("engine.graphics"), Effect::NextStart));
        assert!(matches!(effect_of("control.socket_mode"), Effect::Restart));
        assert!(matches!(effect_of("service.user"), Effect::Restart));
    }
}
