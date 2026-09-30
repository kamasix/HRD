//! Keeping `account list` truthful about stored sessions without asking the
//! secret store 300 times per command: a background pass asks for one account at
//! a time and writes the answer into the registry.

use std::sync::Arc;
use std::time::Duration;

use hrd_core::model::AuthStatus;
use hrd_core::time::now_unix;

use crate::secrets::SecretsState;
use crate::state::Daemon;

/// One pass over every account whose status is only a guess. `Verified` and
/// `Required` come from observing a client and are not overwritten here.
pub fn refresh_all(d: &Daemon) {
    if d.secrets.status().state != SecretsState::Ready {
        return;
    }
    let names: Vec<_> = d.lock().reg.accounts.keys().cloned().collect();
    for n in names {
        if d.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        let profile = d.layout.account_profile(&n, crate::spawn::PROFILE);
        let Ok(present) = d.secrets.session_present(&profile) else {
            return;
        };
        let mut inner = d.lock();
        let Some(a) = inner.reg.accounts.get_mut(&n) else {
            continue;
        };
        let new = match (a.auth.status, present) {
            (AuthStatus::Unknown | AuthStatus::None, true) => Some((
                AuthStatus::Stored,
                "a session is stored; whether Roblox still accepts it is not known",
            )),
            (AuthStatus::Unknown | AuthStatus::Stored, false) => Some((
                AuthStatus::None,
                "nothing is stored: `cordialctl account login`",
            )),
            _ => None,
        };
        if let Some((s, why)) = new {
            a.auth.status = s;
            a.auth.detail = Some(why.into());
            a.auth.checked_at = Some(now_unix());
            let _ = d.save_registry(&inner);
        }
        drop(inner);
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub fn refresh_in_background(d: Arc<Daemon>) {
    std::thread::Builder::new()
        .name("auth-refresh".into())
        .spawn(move || refresh_all(&d))
        .ok();
}

pub fn spawn_periodic(d: Arc<Daemon>) {
    std::thread::Builder::new()
        .name("auth-periodic".into())
        .spawn(move || {
            while !d.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                refresh_all(&d);
                for _ in 0..600 {
                    if d.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        })
        .ok();
}
