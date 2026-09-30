//! The instance state machine, as pure functions over an [`InstanceRecord`].
//!
//! Three rules shape it:
//!
//! * **`connected` needs a signal.** Only `game: joined place` moves an
//!   instance there. A live process, a spawned command or a started join are
//!   `starting`/`joining`.
//! * **Nothing restarts.** Every path out of `connected`, `joining` or
//!   `starting` that is not a stop ends in a terminal state together with
//!   [`Effect::StopSet`], which releases the processes. No path leads back to
//!   `queued`; only an operator command does.
//! * **A disconnect notice is not yet a disconnect.** The engine also prints
//!   one around teleports, so a notice arms a timer and is cancelled by a new
//!   join inside the grace period (`scheduler.disconnect_grace_s`).

use hrd_core::model::{AuthStatus, ExitRecord, InstanceRecord, RunKind, State};

use crate::signals::{screen_is_signed_in, Signal};

#[derive(Debug, Clone, Default)]
pub struct Transient {
    /// When an unanswered disconnect notice was seen.
    pub pending_disconnect_at: Option<u64>,
    pub zero_health_streak: u32,
    pub last_health_at: Option<u64>,
    /// The operator asked for this stop (as opposed to the machine deciding).
    pub operator_stop: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Release the process set: polite stop, then kill.
    StopSet,
    /// What the run learned about the account's session.
    Auth(AuthStatus, String),
}

#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub start_timeout_s: u64,
    pub join_timeout_s: u64,
    pub disconnect_grace_s: u64,
    pub login_timeout_s: u64,
}

pub fn set_state(rec: &mut InstanceRecord, to: State, reason: Option<String>, now: u64) -> bool {
    if rec.state == to && rec.reason == reason {
        return false;
    }
    if rec.state != to {
        rec.state_since = now;
    }
    rec.state = to;
    rec.reason = reason;
    if matches!(
        to,
        State::Disconnected | State::Stopped | State::Failed | State::AuthRequired
    ) {
        rec.ended_at.get_or_insert(now);
    }
    true
}

fn terminal(s: State) -> bool {
    matches!(
        s,
        State::Disconnected
            | State::Stopped
            | State::Failed
            | State::AuthRequired
            | State::Configured
    )
}

fn live_run(s: State) -> bool {
    s.expects_processes()
}

pub fn on_signal(
    rec: &mut InstanceRecord,
    tr: &mut Transient,
    sig: Signal,
    now: u64,
) -> Vec<Effect> {
    let mut fx = Vec::new();
    // A run that has been decided is only being wound down; late lines from the
    // dying client must not revive it.
    if !live_run(rec.state) {
        return fx;
    }
    let login = rec.kind == RunKind::Login;
    match sig {
        Signal::EngineLoaded => {
            rec.signals.engine_loaded_at.get_or_insert(now);
        }
        Signal::Screen(name) => {
            rec.signals.screen = Some(name.clone());
            if screen_is_signed_in(&name) {
                rec.signals.signed_in_at.get_or_insert(now);
                rec.signals.signed_out_at = None;
                fx.push(Effect::Auth(
                    AuthStatus::Verified,
                    format!("the client reached {name}"),
                ));
                if login {
                    set_state(
                        rec,
                        State::Stopped,
                        Some("sign-in complete: the session is stored".into()),
                        now,
                    );
                    fx.push(Effect::StopSet);
                } else if rec.state == State::Starting || rec.state == State::Unknown {
                    set_state(
                        rec,
                        State::Joining,
                        Some("signed in; waiting for the join".into()),
                        now,
                    );
                }
            } else if name == "Landing" {
                rec.signals.signed_out_at.get_or_insert(now);
                if !login {
                    let why = "the client reached the sign-in screen, so no session was accepted; run `cordialctl account login` for this account";
                    fx.push(Effect::Auth(AuthStatus::Required, why.into()));
                    set_state(rec, State::AuthRequired, Some(why.into()), now);
                    fx.push(Effect::StopSet);
                }
            }
        }
        Signal::LoggedIn => {
            rec.signals.signed_in_at.get_or_insert(now);
            fx.push(Effect::Auth(
                AuthStatus::Verified,
                "a sign-in happened in this run".into(),
            ));
        }
        Signal::LoggedOut => {
            rec.signals.signed_out_at = Some(now);
            if !login {
                let why =
                    "the client reported a sign-out: the stored session is no longer accepted";
                fx.push(Effect::Auth(AuthStatus::Required, why.into()));
                set_state(rec, State::AuthRequired, Some(why.into()), now);
                fx.push(Effect::StopSet);
            }
        }
        Signal::LaunchReached => {
            rec.signals.join_requested_at.get_or_insert(now);
            if rec.state == State::Starting || rec.state == State::Unknown {
                set_state(
                    rec,
                    State::Joining,
                    Some("the app shell asked to launch the experience".into()),
                    now,
                );
            }
        }
        Signal::LaunchMissed => {
            // Only meaningful while a launch is pending; in a connected run the
            // line cannot be about this session.
            if !login && rec.state != State::Connected {
                if rec.signals.signed_in_at.is_some() {
                    let why = "the app shell did not launch the experience (check the place id and access)";
                    set_state(rec, State::Failed, Some(why.into()), now);
                } else {
                    let why = "the launch link did not reach an experience and the client is not signed in";
                    fx.push(Effect::Auth(AuthStatus::Required, why.into()));
                    set_state(rec, State::AuthRequired, Some(why.into()), now);
                }
                fx.push(Effect::StopSet);
            }
        }
        Signal::Joining { place } => {
            rec.signals.join_requested_at.get_or_insert(now);
            tr.pending_disconnect_at = None;
            rec.signals.joined_place = Some(place);
            let why = if rec.state == State::Connected {
                "joining another server (teleport)"
            } else {
                "the client is joining a server"
            };
            set_state(rec, State::Joining, Some(why.into()), now);
        }
        Signal::Joined { place } => {
            tr.pending_disconnect_at = None;
            rec.signals.connected_at = Some(now);
            rec.signals.joined_place = Some(place);
            rec.signals.disconnected_at = None;
            rec.signals.disconnect_code = None;
            let why = match rec.place_id {
                Some(want) if want.get() != place => {
                    format!("in place {place} (asked for {want}: the experience moved the client)")
                }
                _ => format!("in place {place}"),
            };
            set_state(rec, State::Connected, Some(why), now);
        }
        Signal::Left => {
            // Through the same grace as a disconnect notice: a teleport also
            // leaves one server before joining the next, and a join within the
            // grace cancels this.
            if !login && rec.state != State::Starting {
                tr.pending_disconnect_at.get_or_insert(now);
            }
        }
        Signal::Health { presents } => {
            tr.last_health_at = Some(now);
            tr.zero_health_streak = if presents == 0 {
                tr.zero_health_streak + 1
            } else {
                0
            };
        }
        Signal::DisconnectNotice { code } => {
            rec.signals.disconnect_code = Some(code);
            if matches!(
                rec.state,
                State::Joining | State::Connected | State::Unknown
            ) && !login
            {
                tr.pending_disconnect_at = Some(now);
            }
        }
    }
    fx
}

pub fn on_tick(rec: &mut InstanceRecord, tr: &mut Transient, t: &Timing, now: u64) -> Vec<Effect> {
    let mut fx = Vec::new();
    if !live_run(rec.state) {
        return fx;
    }
    if let Some(at) = tr.pending_disconnect_at {
        if now.saturating_sub(at) >= t.disconnect_grace_s {
            tr.pending_disconnect_at = None;
            rec.signals.disconnected_at = Some(now);
            let why = match rec.signals.disconnect_code {
                Some(c) => format!("the engine reported a disconnection (reason code {c}) and did not join again within {} s", t.disconnect_grace_s),
                None => format!("the client left the experience and did not join another within {} s", t.disconnect_grace_s),
            };
            set_state(rec, State::Disconnected, Some(why), now);
            fx.push(Effect::StopSet);
            return fx;
        }
    }
    let age = now.saturating_sub(rec.state_since);
    match (rec.kind, rec.state) {
        (RunKind::Login, _) => {
            let started = rec.started_at.unwrap_or(rec.state_since);
            if now.saturating_sub(started) >= t.login_timeout_s {
                set_state(
                    rec,
                    State::Stopped,
                    Some("the sign-in session timed out".into()),
                    now,
                );
                fx.push(Effect::StopSet);
            }
        }
        (RunKind::Play, State::Starting) if age >= t.start_timeout_s => {
            let why = format!("did not reach the first screen in {} s (BASELINE: the startup freeze is a documented failure mode)", t.start_timeout_s);
            set_state(rec, State::Failed, Some(why), now);
            fx.push(Effect::StopSet);
        }
        (RunKind::Play, State::Joining) if age >= t.join_timeout_s => {
            let why = format!(
                "did not report joining the experience within {} s",
                t.join_timeout_s
            );
            set_state(rec, State::Failed, Some(why), now);
            fx.push(Effect::StopSet);
        }
        _ => {}
    }
    fx
}

/// The main process is gone (and the rest of the set is about to be).
pub fn on_exit(rec: &mut InstanceRecord, tr: &Transient, exit: ExitRecord, now: u64) {
    let how = describe_exit(&exit);
    rec.exit = Some(exit.clone());
    rec.ended_at.get_or_insert(now);
    if tr.operator_stop {
        if live_run(rec.state) || rec.state == State::Queued {
            set_state(
                rec,
                State::Stopped,
                Some("stopped by the operator".into()),
                now,
            );
        }
        return;
    }
    if terminal(rec.state) {
        // Already decided (stopped by the machine); keep that verdict.
        return;
    }
    if rec.kind == RunKind::Login {
        set_state(
            rec,
            State::Failed,
            Some(format!(
                "the sign-in client ended before sign-in completed ({how})"
            )),
            now,
        );
        return;
    }
    if rec.signals.connected_at.is_some() {
        rec.signals.disconnected_at = Some(now);
        set_state(
            rec,
            State::Disconnected,
            Some(format!(
                "the client process ended after having been connected ({how})"
            )),
            now,
        );
        return;
    }
    let why = if exit.oom_killed {
        "killed by the kernel out-of-memory killer before joining".to_string()
    } else {
        match exit.code {
            Some(3) => "the profile is locked by another process (exit 3)".to_string(),
            Some(124) => "the engine's teardown watchdog fired (exit 124)".to_string(),
            _ => format!("the client ended before joining ({how})"),
        }
    };
    set_state(rec, State::Failed, Some(why), now);
}

pub fn describe_exit(e: &ExitRecord) -> String {
    if e.unobserved {
        return "exit status not observed".into();
    }
    match (e.code, e.signal) {
        (Some(c), _) => format!("exit code {c}"),
        (None, Some(s)) => format!("signal {s}"),
        _ => "no status".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hrd_core::ids::{AccountName, PlaceId};

    fn rec(kind: RunKind) -> InstanceRecord {
        let mut r = InstanceRecord::new(AccountName::new("a").unwrap(), 100);
        r.state = State::Starting;
        r.kind = kind;
        r.started_at = Some(100);
        r.place_id = PlaceId::new(7).ok();
        r
    }
    const T: Timing = Timing {
        start_timeout_s: 300,
        join_timeout_s: 300,
        disconnect_grace_s: 20,
        login_timeout_s: 900,
    };

    #[test]
    fn a_process_alone_is_never_connected() {
        let mut r = rec(RunKind::Play);
        let mut tr = Transient::default();
        on_signal(&mut r, &mut tr, Signal::EngineLoaded, 101);
        on_signal(&mut r, &mut tr, Signal::Health { presents: 30 }, 130);
        assert_eq!(r.state, State::Starting);
        on_signal(&mut r, &mut tr, Signal::Screen("Home".into()), 140);
        assert_eq!(r.state, State::Joining);
        on_signal(&mut r, &mut tr, Signal::Joined { place: 7 }, 150);
        assert_eq!(r.state, State::Connected);
        assert_eq!(r.signals.connected_at, Some(150));
    }

    #[test]
    fn the_sign_in_screen_makes_a_play_run_auth_required_and_releases_it() {
        let mut r = rec(RunKind::Play);
        let mut tr = Transient::default();
        let fx = on_signal(&mut r, &mut tr, Signal::Screen("Landing".into()), 110);
        assert_eq!(r.state, State::AuthRequired);
        assert!(fx.contains(&Effect::StopSet));
        assert!(fx
            .iter()
            .any(|e| matches!(e, Effect::Auth(AuthStatus::Required, _))));
        assert!(r.reason.as_deref().unwrap().contains("account login"));
    }

    #[test]
    fn landing_is_what_a_sign_in_run_expects() {
        let mut r = rec(RunKind::Login);
        let mut tr = Transient::default();
        let fx = on_signal(&mut r, &mut tr, Signal::Screen("Landing".into()), 110);
        assert_eq!(r.state, State::Starting);
        assert!(fx.is_empty());
        let fx = on_signal(&mut r, &mut tr, Signal::Screen("Home".into()), 200);
        assert_eq!(r.state, State::Stopped);
        assert!(fx.contains(&Effect::StopSet));
    }

    #[test]
    fn a_notice_followed_by_a_join_is_a_teleport_not_a_disconnect() {
        let mut r = rec(RunKind::Play);
        let mut tr = Transient::default();
        on_signal(&mut r, &mut tr, Signal::Joined { place: 7 }, 200);
        on_signal(&mut r, &mut tr, Signal::DisconnectNotice { code: 267 }, 300);
        assert!(on_tick(&mut r, &mut tr, &T, 310).is_empty());
        on_signal(&mut r, &mut tr, Signal::Joining { place: 8 }, 312);
        assert!(on_tick(&mut r, &mut tr, &T, 400)
            .iter()
            .all(|e| *e != Effect::StopSet));
        assert_eq!(r.state, State::Joining);
    }

    #[test]
    fn an_unanswered_notice_becomes_a_disconnect_with_its_code_and_frees_the_set() {
        let mut r = rec(RunKind::Play);
        let mut tr = Transient::default();
        on_signal(&mut r, &mut tr, Signal::Joined { place: 7 }, 200);
        on_signal(&mut r, &mut tr, Signal::DisconnectNotice { code: 267 }, 300);
        assert_eq!(r.state, State::Connected, "not yet");
        let fx = on_tick(&mut r, &mut tr, &T, 321);
        assert_eq!(r.state, State::Disconnected);
        assert_eq!(r.signals.disconnect_code, Some(267));
        assert!(r.reason.as_deref().unwrap().contains("267"));
        assert_eq!(fx, vec![Effect::StopSet]);
    }

    #[test]
    fn leaving_one_server_and_joining_the_next_is_not_a_disconnect() {
        let mut r = rec(RunKind::Play);
        let mut tr = Transient::default();
        on_signal(&mut r, &mut tr, Signal::Joined { place: 7 }, 200);
        on_signal(&mut r, &mut tr, Signal::Left, 210);
        on_signal(&mut r, &mut tr, Signal::Joining { place: 8 }, 212);
        on_tick(&mut r, &mut tr, &T, 400);
        assert_ne!(r.state, State::Disconnected);
    }

    #[test]
    fn nothing_after_a_disconnect_revives_the_run() {
        let mut r = rec(RunKind::Play);
        let mut tr = Transient::default();
        on_signal(&mut r, &mut tr, Signal::Joined { place: 7 }, 200);
        on_signal(&mut r, &mut tr, Signal::Left, 210);
        assert_eq!(r.state, State::Connected, "left waits for the grace");
        on_tick(&mut r, &mut tr, &T, 400);
        assert_eq!(r.state, State::Disconnected);
        for s in [
            Signal::Joined { place: 7 },
            Signal::Joining { place: 7 },
            Signal::Screen("Home".into()),
        ] {
            assert!(on_signal(&mut r, &mut tr, s, 220).is_empty());
            assert_eq!(r.state, State::Disconnected);
        }
    }

    #[test]
    fn timeouts_fail_a_stuck_start_and_a_stuck_join() {
        let mut r = rec(RunKind::Play);
        r.state_since = 100;
        let mut tr = Transient::default();
        assert!(on_tick(&mut r, &mut tr, &T, 399).is_empty());
        assert!(on_tick(&mut r, &mut tr, &T, 400).contains(&Effect::StopSet));
        assert_eq!(r.state, State::Failed);
        let mut r = rec(RunKind::Play);
        r.state = State::Joining;
        r.state_since = 100;
        on_tick(&mut r, &mut tr, &T, 401);
        assert_eq!(r.state, State::Failed);
    }

    #[test]
    fn a_sign_in_session_ends_at_its_own_deadline() {
        let mut r = rec(RunKind::Login);
        let mut tr = Transient::default();
        assert!(!on_tick(&mut r, &mut tr, &T, 1000).is_empty());
        assert_eq!(r.state, State::Stopped);
    }

    #[test]
    fn exits_are_classified() {
        let ex = |code: Option<i32>, oom: bool| ExitRecord {
            code,
            signal: None,
            oom_killed: oom,
            unobserved: false,
        };
        let tr = Transient::default();
        let mut r = rec(RunKind::Play);
        on_exit(&mut r, &tr, ex(Some(3), false), 150);
        assert_eq!(r.state, State::Failed);
        assert!(r.reason.as_deref().unwrap().contains("locked"));
        let mut r = rec(RunKind::Play);
        on_exit(&mut r, &tr, ex(None, true), 150);
        assert!(r.reason.as_deref().unwrap().contains("out-of-memory"));
        let mut r = rec(RunKind::Play);
        r.state = State::Connected;
        r.signals.connected_at = Some(120);
        on_exit(&mut r, &tr, ex(Some(0), false), 150);
        assert_eq!(r.state, State::Disconnected);
        let mut r = rec(RunKind::Play);
        let tr2 = Transient {
            operator_stop: true,
            ..Default::default()
        };
        on_exit(&mut r, &tr2, ex(None, false), 150);
        assert_eq!(r.state, State::Stopped);
    }

    #[test]
    fn a_verdict_the_machine_already_reached_survives_the_exit() {
        let mut r = rec(RunKind::Play);
        let mut tr = Transient::default();
        on_signal(&mut r, &mut tr, Signal::Joined { place: 7 }, 200);
        on_signal(&mut r, &mut tr, Signal::Left, 210);
        on_tick(&mut r, &mut tr, &T, 400);
        let why = r.reason.clone();
        on_exit(
            &mut r,
            &tr,
            ExitRecord {
                code: None,
                signal: Some(9),
                oom_killed: false,
                unobserved: false,
            },
            215,
        );
        assert_eq!(r.state, State::Disconnected);
        assert_eq!(r.reason, why);
    }
}
