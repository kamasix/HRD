//! What a client's log lines say about it.
//!
//! Pure: a line in, at most one [`Signal`] out. The formats are the ones the
//! open layer prints (`game_log.rs`, `deeplink.rs`, `looper.rs`, `load.rs`) and
//! the engine's own file log; every pattern below is quoted from those sources
//! and nothing else is inferred. **None has been observed against a running
//! client in this project** (docs/status.md): they were read in source.
//!
//! Matching is by substring, never by position, so a timestamp prefix or a new
//! trailing field does not break it. A line that is not recognised is nothing,
//! not an error.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    /// `LOADED in 25ms`: the engine library is mapped and initialised.
    EngineLoaded,
    /// `[roblox] app ready: <Screen>`. `Landing` is the signed-out screen;
    /// `Home` and `RootSwitchNavigator` are signed-in ones.
    Screen(String),
    /// `DID_LOG_IN` notification: a sign-in happened in this run.
    LoggedIn,
    /// `DID_LOG_OUT` or `LUA_UNAUTHORIZED_LOG_OUT`.
    LoggedOut,
    /// `[deeplink] the app shell asked to launch an experience`.
    LaunchReached,
    /// `[deeplink] ... did not reach an experience`.
    LaunchMissed,
    /// `[cordial] game: joining server <job> of place <id>`.
    Joining { place: u64 },
    /// `[cordial] game: joined place <id> (universe <u>) as <user>`. The user
    /// id is deliberately not carried.
    Joined { place: u64 },
    /// `[cordial] game: left`: the engine returned to its own home screen.
    Left,
    /// `[cordial] health: N presents in Ss`.
    Health { presents: u64 },
    /// `Disconnection Notification. Reason: N` from the engine's file log.
    DisconnectNotice { code: i64 },
}

pub fn parse_line(line: &str) -> Option<Signal> {
    if line.contains("LOADED in ") && line.trim_start().starts_with("LOADED in") {
        return Some(Signal::EngineLoaded);
    }
    if let Some(rest) = after(line, "[roblox] app ready: ") {
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            return Some(Signal::Screen(name));
        }
    }
    if line.contains("datamodel notification: DID_LOG_IN") {
        return Some(Signal::LoggedIn);
    }
    if line.contains("datamodel notification: DID_LOG_OUT")
        || line.contains("datamodel notification: LUA_UNAUTHORIZED_LOG_OUT")
    {
        return Some(Signal::LoggedOut);
    }
    if line.contains("[deeplink] the app shell asked to launch an experience") {
        return Some(Signal::LaunchReached);
    }
    if line.contains("[deeplink] the app shell is up and nothing asked to launch an experience") {
        return Some(Signal::LaunchMissed);
    }
    if let Some(rest) = after(line, "[cordial] game: joining server ") {
        let place = rest.split(" of place ").nth(1).and_then(number)?;
        return Some(Signal::Joining { place });
    }
    if let Some(rest) = after(line, "[cordial] game: joined place ") {
        return Some(Signal::Joined {
            place: number(rest)?,
        });
    }
    if line.trim_end().ends_with("[cordial] game: left") {
        return Some(Signal::Left);
    }
    if let Some(rest) = after(line, "[cordial] health: ") {
        let presents = number(rest)?;
        if rest.contains(" presents in ") {
            return Some(Signal::Health { presents });
        }
    }
    if let Some(rest) = after(line, "Disconnection Notification. Reason:") {
        let code = rest
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '-')
            .collect::<String>()
            .parse()
            .ok()?;
        return Some(Signal::DisconnectNotice { code });
    }
    None
}

fn after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.find(marker).map(|i| &line[i + marker.len()..])
}

fn number(s: &str) -> Option<u64> {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

/// Screens that mean a session is signed in.
pub fn screen_is_signed_in(s: &str) -> bool {
    matches!(s, "Home" | "RootSwitchNavigator")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lines_upstream_prints_are_recognised() {
        use Signal::*;
        let cases: &[(&str, Option<Signal>)] = &[
            ("LOADED in 25ms", Some(EngineLoaded)),
            ("[roblox] app ready: Landing", Some(Screen("Landing".into()))),
            ("12:00:01 [roblox] app ready: RootSwitchNavigator", Some(Screen("RootSwitchNavigator".into()))),
            ("[roblox] datamodel notification: DID_LOG_IN <identity elided, 161 bytes>", Some(LoggedIn)),
            ("[roblox] datamodel notification: LUA_UNAUTHORIZED_LOG_OUT", Some(LoggedOut)),
            ("[deeplink] the app shell asked to launch an experience; the link reached the engine", Some(LaunchReached)),
            ("[deeplink] the app shell is up and nothing asked to launch an experience — this link did not reach an experience. Signing in is required before a join can proceed", Some(LaunchMissed)),
            ("[cordial] game: joining server 0123456789abcdef0123456789abcdef0123 of place 920587237", Some(Joining { place: 920587237 })),
            ("[cordial] game: joined place 920587237 (universe 55) as 1234", Some(Joined { place: 920587237 })),
            ("[cordial] game: left", Some(Left)),
            ("[cordial] health: 31 presents in 30s (1.0/s), 100 total", Some(Health { presents: 31 })),
            ("2026-08-31T03:16:55.333Z,316.333221,5b43f6c0,7 [FLog::Network] Disconnection Notification. Reason: 267", Some(DisconnectNotice { code: 267 })),
        ];
        for (line, want) in cases {
            assert_eq!(&parse_line(line), want, "{line}");
        }
    }

    #[test]
    fn disconnect_shaped_lines_that_are_not_notices_are_nothing() {
        for line in [
            "2026-08-31T03:14:53.338Z,194.338837,bf08c6c0,6,Info [DFLog::NetworkClient] Client:Disconnect",
            "[FLog::Network] Connection lost: connectMode: Peer Disconnected, timeMS:316332",
            "Disconnected - Websocket error: 401 Unauthorized",
            "[cordial] game: server 128.116.51.33:50363",
            "Disconnection Notification. Reason: soon",
            "",
            "not a log line",
        ] {
            assert_eq!(parse_line(line), None, "{line}");
        }
    }

    #[test]
    fn the_user_id_never_leaves_the_parser() {
        let s = parse_line("[cordial] game: joined place 7 (universe 8) as 999999");
        assert_eq!(s, Some(Signal::Joined { place: 7 }));
    }

    #[test]
    fn only_the_signed_in_screens_count() {
        assert!(screen_is_signed_in("Home"));
        assert!(screen_is_signed_in("RootSwitchNavigator"));
        for s in ["Landing", "Startup", "PlatformAccountRouter"] {
            assert!(!screen_is_signed_in(s));
        }
    }
}
