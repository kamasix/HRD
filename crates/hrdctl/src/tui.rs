//! `hrdctl tui`: a terminal panel that is only a client of the daemon.
//!
//! Leaving it (q, Esc or Ctrl-C) closes the panel and nothing else: no client is
//! stopped, because the panel never owns one. Stopping is an explicit key with a
//! confirmation.

use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Row, Table, TableState, Wrap};
use ratatui::{DefaultTerminal, Frame};

use hrd_core::ids::AccountName;
use hrd_core::model::State;
use hrd_core::proto::{Filter, InstanceDetail, InstanceView, Request, StatsView};
use hrd_core::wire::Client;
use hrd_core::{Error, Result};

use crate::util::{age, mib, opt, pct};
use crate::Ctx;

struct App {
    client: Client,
    rows: Vec<InstanceView>,
    stats: Option<StatsView>,
    state: TableState,
    filter: Option<State>,
    live_only: bool,
    overlay: Overlay,
    message: String,
    last_fetch: Instant,
    error: Option<String>,
}

enum Overlay {
    None,
    Detail(Box<InstanceDetail>),
    Logs(String, Vec<String>),
    ConfirmStop(AccountName),
    ConfirmStopAll,
    Help,
}

const FILTERS: [Option<State>; 6] = [
    None,
    Some(State::Connected),
    Some(State::Disconnected),
    Some(State::Failed),
    Some(State::AuthRequired),
    Some(State::Queued),
];

impl App {
    fn selected(&self) -> Option<&InstanceView> {
        self.state.selected().and_then(|i| self.rows.get(i))
    }

    fn fetch(&mut self) {
        let states = match (self.filter, self.live_only) {
            (Some(s), _) => vec![s],
            (None, true) => vec![
                State::Queued,
                State::Starting,
                State::Joining,
                State::Connected,
                State::Unknown,
            ],
            (None, false) => vec![],
        };
        let rows: Result<Vec<InstanceView>> = self.client.call(Request::Status {
            filter: Filter {
                states,
                ..Default::default()
            },
        });
        let stats: Result<StatsView> = self.client.call(Request::Stats {
            filter: Filter::default(),
        });
        match (rows, stats) {
            (Ok(r), Ok(s)) => {
                self.rows = r;
                self.stats = Some(s);
                self.error = None;
                let n = self.rows.len();
                match self.state.selected() {
                    Some(i) if i >= n => self.state.select(n.checked_sub(1)),
                    None if n > 0 => self.state.select(Some(0)),
                    _ => {}
                }
            }
            (Err(e), _) | (_, Err(e)) => self.error = Some(e.to_string()),
        }
        self.last_fetch = Instant::now();
    }

    fn act_detail(&mut self) {
        if let Some(id) = self.selected().map(|i| i.id.clone()) {
            match self
                .client
                .call::<InstanceDetail>(Request::InstanceShow { id })
            {
                Ok(d) => self.overlay = Overlay::Detail(Box::new(d)),
                Err(e) => self.message = e.to_string(),
            }
        }
    }

    fn act_logs(&mut self) {
        if let Some(id) = self.selected().map(|i| i.id.clone()) {
            match self.client.call::<Vec<String>>(Request::Logs {
                id: id.clone(),
                lines: 200,
                follow: false,
            }) {
                Ok(l) => self.overlay = Overlay::Logs(id.to_string(), l),
                Err(e) => self.message = e.to_string(),
            }
        }
    }

    fn stop(&mut self, id: AccountName) {
        self.message = match self.client.call_value(Request::InstanceStop {
            id: id.clone(),
            force: false,
        }) {
            Ok(_) => format!("{id}: stopping"),
            Err(e) => e.to_string(),
        };
        self.fetch();
    }

    fn stop_all(&mut self) {
        self.message = match self.client.call_value(Request::StopAll { force: false }) {
            Ok(v) => format!("stopping {} instance(s)", v["stopping"]),
            Err(e) => e.to_string(),
        };
        self.fetch();
    }

    /// Returns false to leave.
    fn key(&mut self, code: KeyCode, mods: KeyModifiers) -> bool {
        if mods.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
            return false;
        }
        match &self.overlay {
            Overlay::ConfirmStop(id) => {
                let id = id.clone();
                self.overlay = Overlay::None;
                if code == KeyCode::Char('y') {
                    self.stop(id);
                } else {
                    self.message = "not stopped".into();
                }
                return true;
            }
            Overlay::ConfirmStopAll => {
                self.overlay = Overlay::None;
                if code == KeyCode::Char('y') {
                    self.stop_all();
                } else {
                    self.message = "not stopped".into();
                }
                return true;
            }
            Overlay::None => {}
            _ => {
                if matches!(code, KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter) {
                    self.overlay = Overlay::None;
                }
                return true;
            }
        }
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return false,
            KeyCode::Down | KeyCode::Char('j') => self.state.select_next(),
            KeyCode::Up | KeyCode::Char('k') => self.state.select_previous(),
            KeyCode::PageDown => (0..10).for_each(|_| self.state.select_next()),
            KeyCode::PageUp => (0..10).for_each(|_| self.state.select_previous()),
            KeyCode::Home | KeyCode::Char('g') => self.state.select_first(),
            KeyCode::End | KeyCode::Char('G') => self.state.select_last(),
            KeyCode::Enter => self.act_detail(),
            KeyCode::Char('l') => self.act_logs(),
            KeyCode::Char('r') => self.fetch(),
            KeyCode::Char('a') => {
                self.live_only = !self.live_only;
                self.fetch();
            }
            KeyCode::Char('f') => {
                let i = FILTERS.iter().position(|f| *f == self.filter).unwrap_or(0);
                self.filter = FILTERS[(i + 1) % FILTERS.len()];
                self.fetch();
            }
            KeyCode::Char('x') => {
                if let Some(v) = self.selected() {
                    if v.state.is_live() {
                        self.overlay = Overlay::ConfirmStop(v.id.clone());
                    } else {
                        self.message = format!("{} is {}: nothing to stop", v.id, v.state);
                    }
                }
            }
            KeyCode::Char('X') => self.overlay = Overlay::ConfirmStopAll,
            KeyCode::Char('?') | KeyCode::Char('h') => self.overlay = Overlay::Help,
            _ => {}
        }
        true
    }
}

fn state_style(s: State) -> Style {
    let c = match s {
        State::Connected => Color::Green,
        State::Starting | State::Joining | State::Queued => Color::Yellow,
        State::Failed | State::AuthRequired => Color::Red,
        State::Disconnected => Color::Magenta,
        State::Unknown => Color::Cyan,
        _ => Color::Gray,
    };
    Style::default().fg(c)
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(h.min(area.height)),
            Constraint::Fill(1),
        ])
        .split(area)[1];
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(w.min(area.width)),
            Constraint::Fill(1),
        ])
        .split(v)[1]
}

const HEADS: [&str; 10] = [
    "ID",
    "STATE",
    "GROUP",
    "PROXY GROUP",
    "PLACE",
    "UP",
    "RSS MiB",
    "PSS MiB",
    "CPU%",
    "WHY",
];

/// One row's cells, in the order of [`HEADS`].
fn row_cells(i: &InstanceView) -> Vec<String> {
    let m = i.mem.clone().unwrap_or_default();
    vec![
        i.id.to_string(),
        i.state.to_string(),
        opt(&i.group),
        opt(&i.proxy_group),
        opt(&i.place_id),
        age(i.uptime_s),
        mib(m.rss_bytes),
        mib(m.pss_bytes),
        pct(i.cpu_percent),
        i.reason.clone().unwrap_or_default(),
    ]
}

/// Which columns to show and how wide each is, for a table `room` characters
/// wide. Widths come from the data, because names go up to 24 characters; the
/// last column (WHY) takes what is left, and the least useful columns drop out
/// when that would be under 20 characters.
fn layout(cells: &[Vec<String>], room: usize) -> (Vec<usize>, [u16; 9]) {
    let caps: [usize; 9] = [24, 13, 24, 24, 14, 8, 8, 8, 5];
    let mut width = [0u16; 9];
    for (c, w) in width.iter_mut().enumerate() {
        let longest = cells
            .iter()
            .map(|r| r[c].chars().count())
            .max()
            .unwrap_or(0)
            .max(HEADS[c].chars().count());
        *w = longest.min(caps[c]) as u16;
    }
    let mut shown: Vec<usize> = (0..9).collect();
    let need = |shown: &[usize]| shown.iter().map(|&c| width[c] as usize + 1).sum::<usize>() + 20;
    for drop in [5usize, 7, 6, 4] {
        if need(&shown) <= room {
            break;
        }
        shown.retain(|&c| c != drop);
    }
    (shown, width)
}

fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Fill(1),
            Constraint::Length(2),
        ])
        .split(area);

    let mut head = vec![];
    if let Some(s) = &app.stats {
        head.push(Line::from(format!(
            "instances {}  engines RSS {} / PSS {} MiB   compositors PSS {}   helpers PSS {}   total PSS {} MiB   cpu {}%",
            s.instances,
            mib(s.engines.rss_bytes),
            mib(s.engines.pss_bytes),
            mib(s.compositors.pss_bytes),
            mib(s.helpers.pss_bytes),
            mib(s.total.pss_bytes),
            pct(s.total.cpu_percent)
        )));
        head.push(Line::from(format!(
            "available {} MiB   memory pressure {}   cgroup memory.current {} MiB   (\"-\" = not measured; RSS double-counts shared pages, PSS does not)",
            mib(s.mem_available_bytes),
            s.memory_pressure_some_avg10.map(|p| format!("{p:.1}%")).unwrap_or_else(|| "-".into()),
            mib(s.cgroup_current_bytes)
        )));
    }
    if let Some(e) = &app.error {
        head.push(Line::styled(
            format!("daemon: {e}"),
            Style::default().fg(Color::Red),
        ));
    }
    let filt = match (app.filter, app.live_only) {
        (Some(s), _) => format!("state = {s}"),
        (None, true) => "live only".to_string(),
        (None, false) => "all".to_string(),
    };
    f.render_widget(
        Paragraph::new(head).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" HRD — {} shown, filter: {filt} ", app.rows.len())),
        ),
        parts[0],
    );

    let cells: Vec<Vec<String>> = app.rows.iter().map(row_cells).collect();
    let (shown, width) = layout(&cells, parts[1].width.saturating_sub(2) as usize);
    let header = Row::new(
        shown
            .iter()
            .map(|&c| HEADS[c])
            .chain(std::iter::once(HEADS[9])),
    )
    .style(Style::default().add_modifier(Modifier::BOLD));
    let rows: Vec<Row> = app
        .rows
        .iter()
        .zip(&cells)
        .map(|(i, r)| {
            Row::new(
                shown
                    .iter()
                    .map(|&c| r[c].clone())
                    .chain(std::iter::once(r[9].clone())),
            )
            .style(state_style(i.state))
        })
        .collect();
    let widths: Vec<Constraint> = shown
        .iter()
        .map(|&c| Constraint::Length(width[c]))
        .chain(std::iter::once(Constraint::Fill(1)))
        .collect();
    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .block(Block::default().borders(Borders::ALL));
    f.render_stateful_widget(table, parts[1], &mut app.state);

    let help = "↑↓ select  Enter details  l log  f state filter  a live only  r refresh  x stop selected  X stop all  ? help  q quit (clients keep running)";
    f.render_widget(
        Paragraph::new(vec![
            Line::from(help),
            Line::styled(app.message.clone(), Style::default().fg(Color::Yellow)),
        ]),
        parts[2],
    );

    match &app.overlay {
        Overlay::None => {}
        Overlay::Help => {
            let r = centered(area, 70, 14);
            f.render_widget(Clear, r);
            let text = "The panel only talks to the daemon. Leaving it stops nothing.\n\nx  stop the selected client (asks first)\nX  stop every client (asks first)\nf  cycle the state filter\na  show only live instances\nEnter  details of the selected instance\nl  its last 200 log lines (credentials scrubbed)\n\nStarting, signing in and proxy changes are done with hrdctl.";
            f.render_widget(
                Paragraph::new(text)
                    .wrap(Wrap { trim: false })
                    .block(Block::default().borders(Borders::ALL).title(" help ")),
                r,
            );
        }
        Overlay::ConfirmStop(id) => {
            let r = centered(area, 50, 5);
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(format!("Stop {id}? (y/n)"))
                    .block(Block::default().borders(Borders::ALL).title(" confirm ")),
                r,
            );
        }
        Overlay::ConfirmStopAll => {
            let r = centered(area, 50, 5);
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new("Stop EVERY client and cancel the queue? (y/n)")
                    .block(Block::default().borders(Borders::ALL).title(" confirm ")),
                r,
            );
        }
        Overlay::Logs(id, lines) => {
            let r = centered(
                area,
                area.width.saturating_sub(4),
                area.height.saturating_sub(4),
            );
            f.render_widget(Clear, r);
            let keep = r.height.saturating_sub(2) as usize;
            let from = lines.len().saturating_sub(keep);
            let text: Vec<Line> = lines[from..]
                .iter()
                .map(|l| Line::from(l.as_str()))
                .collect();
            f.render_widget(
                Paragraph::new(text).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!(" log of {id} (Esc closes) ")),
                ),
                r,
            );
        }
        Overlay::Detail(d) => {
            let r = centered(
                area,
                area.width.saturating_sub(6),
                area.height.saturating_sub(4),
            );
            f.render_widget(Clear, r);
            let v = &d.view;
            let s = &d.record.signals;
            let mut t = vec![
                Line::from(vec![Span::styled(v.id.to_string(), Style::default().add_modifier(Modifier::BOLD)), Span::raw(format!("  {}  {}", v.state, v.reason.clone().unwrap_or_default()))]),
                Line::from(format!("group {}  proxy group {}  place {}  run {}  mode {}  runtime {}", opt(&v.group), opt(&v.proxy_group), opt(&v.place_id), v.run, v.mode.as_str(), opt(&v.runtime))),
                Line::from(format!("signals: loaded {}  signed-in {}  connected {}  disconnected {}  code {}  screen {}", opt(&s.engine_loaded_at), opt(&s.signed_in_at), opt(&s.connected_at), opt(&s.disconnected_at), opt(&s.disconnect_code), opt(&s.screen))),
            ];
            if let Some(m) = &v.mem {
                t.push(Line::from(format!(
                    "RSS {} MiB  PSS {} MiB  USS {} MiB  swap {} MiB  cgroup {} MiB",
                    mib(m.rss_bytes),
                    mib(m.pss_bytes),
                    mib(m.uss_bytes),
                    mib(m.swap_bytes),
                    mib(m.cgroup_current_bytes)
                )));
            }
            for m in &d.members {
                t.push(Line::from(format!(
                    "  {:>7} {:<10} {:<24} {:>8} MiB",
                    m.pid,
                    m.class,
                    m.name,
                    mib(m.rss_bytes)
                )));
            }
            t.push(Line::from(""));
            t.extend(d.log_tail.iter().map(|l| Line::from(l.as_str())));
            f.render_widget(
                Paragraph::new(t).wrap(Wrap { trim: false }).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" details (Esc closes) "),
                ),
                r,
            );
        }
    }
}

fn event_loop(term: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    app.fetch();
    loop {
        term.draw(|f| draw(f, app))
            .map_err(|e| Error::io("draw", e))?;
        if event::poll(Duration::from_millis(250)).map_err(|e| Error::io("read the keyboard", e))? {
            if let Event::Key(k) = event::read().map_err(|e| Error::io("read the keyboard", e))? {
                if k.kind == KeyEventKind::Press && !app.key(k.code, k.modifiers) {
                    return Ok(());
                }
            }
        }
        if app.last_fetch.elapsed() > Duration::from_secs(2) && matches!(app.overlay, Overlay::None)
        {
            app.fetch();
        }
    }
}

pub fn run(ctx: &Ctx) -> Result<()> {
    if ctx.out.json {
        return Err(Error::invalid("the terminal panel has no JSON mode"));
    }
    let client = ctx.client()?;
    let mut app = App {
        client,
        rows: vec![],
        stats: None,
        state: TableState::default(),
        filter: None,
        live_only: false,
        overlay: Overlay::None,
        message: String::new(),
        last_fetch: Instant::now(),
        error: None,
    };
    let mut term = ratatui::init();
    let r = event_loop(&mut term, &mut app);
    ratatui::restore();
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cells(id: &str, group: &str, proxy_group: &str, why: &str) -> Vec<String> {
        [
            id,
            "failed",
            group,
            proxy_group,
            "920587237",
            "-",
            "-",
            "-",
            "-",
            why,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    #[test]
    fn long_names_get_their_full_width() {
        let rows = vec![cells(
            "an-account-with-24-chars",
            "adopt-me-eu-west-extra-1",
            "de-frankfurt-1-second-pg",
            "gone",
        )];
        let (shown, width) = layout(&rows, 200);
        assert_eq!(shown.len(), 9, "everything fits in 200 columns");
        assert_eq!(width[0], 24);
        assert_eq!(width[2], 24);
        assert_eq!(width[3], 24);
    }

    #[test]
    fn a_narrow_terminal_drops_columns_before_squeezing_why() {
        let rows = vec![cells("alt-01", "adopt-me", "de-1", "the client exited")];
        let (wide, _) = layout(&rows, 120);
        assert_eq!(wide.len(), 9);
        let (narrow, width) = layout(&rows, 70);
        assert!(narrow.len() < 9, "something was dropped");
        assert!(!narrow.contains(&5), "UP goes first");
        let used: usize = narrow.iter().map(|&c| width[c] as usize + 1).sum();
        assert!(
            used + 20 <= 70 || narrow.len() == 5,
            "WHY keeps 20 or nothing more can go"
        );
    }

    #[test]
    fn no_rows_still_lays_out() {
        let (shown, width) = layout(&[], 80);
        assert!(!shown.is_empty());
        assert_eq!(width[0], 2, "the ID header");
    }
}
