//! Live view of the audit log. Refreshes twice a second. Press `q` to quit.

use crate::audit::{format_ts, AuditLog, Counts, Event};
use crate::Result;
use crossterm::event::{self, Event as TermEvent, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Terminal;
use std::io::{self, IsTerminal};
use std::path::Path;
use std::time::Duration;

pub fn run(db: &Path) -> Result<()> {
    if !io::stdout().is_terminal() {
        return Err(crate::Error::new(
            "stdout is not a terminal. Use `keyalibi audit` to read the log.",
        ));
    }
    let _restore = RestoreTerminal::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    loop {
        let (counts, events) = load(db).unwrap_or_else(|_| (Counts::default(), Vec::new()));
        terminal.draw(|frame| draw(frame, &counts, &events, db))?;
        if event::poll(Duration::from_millis(500))? {
            if let TermEvent::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press
                    && matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
                {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn load(db: &Path) -> Result<(Counts, Vec<Event>)> {
    if !db.exists() {
        return Ok((Counts::default(), Vec::new()));
    }
    let log = AuditLog::open(db)?;
    Ok((log.counts()?, log.recent(20)?))
}

fn draw(frame: &mut ratatui::Frame, counts: &Counts, events: &[Event], db: &Path) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(8),
        ])
        .split(frame.area());
    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            " KeyAlibi ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  phantom credentials stay in the supervisor"),
    ]))
    .block(Block::default().borders(Borders::ALL).title(" session "));
    frame.render_widget(title, chunks[0]);

    let stats = format!(
        " minted {mint}    swapped {swap}    scrubbed {scrub}    blocked {block}\n log {path}",
        mint = counts.mint,
        swap = counts.swap,
        scrub = counts.scrub,
        block = counts.block,
        path = db.display()
    );
    let stats = Paragraph::new(stats).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" injections / swaps / blocks "),
    );
    frame.render_widget(stats, chunks[1]);

    let mut lines = Vec::new();
    if events.is_empty() {
        lines.push(Line::from(" no events yet"));
    }
    for event in events {
        let color = match event.severity.as_str() {
            "critical" => Color::Red,
            "info" => Color::Green,
            _ => Color::Yellow,
        };
        lines.push(Line::from(vec![
            Span::raw(format!("{} ", format_ts(event.ts))),
            Span::styled(format!("{:<8}", event.kind), Style::default().fg(color)),
            Span::raw(format!(
                " {} {} {}",
                event.env_var, event.destination, event.detail
            )),
        ]));
    }
    let body = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" recent events  (q quits) "),
    );
    frame.render_widget(body, chunks[2]);
}

struct RestoreTerminal;

impl RestoreTerminal {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for RestoreTerminal {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}
