//! SQLite audit log of mints, swaps, scrubs, and blocked exfiltration attempts.
//!
//! Rows store env var names and destinations, never secret bytes.

use crate::{Error, Result};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct Event {
    pub id: i64,
    pub ts: i64,
    pub kind: String,
    pub severity: String,
    pub child_pid: Option<i32>,
    pub command: String,
    pub destination: String,
    pub env_var: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct Counts {
    pub mint: u64,
    pub swap: u64,
    pub scrub: u64,
    pub block: u64,
    pub other: u64,
}

pub struct AuditLog {
    conn: Mutex<Connection>,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                child_pid INTEGER,
                command TEXT NOT NULL DEFAULT '',
                destination TEXT NOT NULL DEFAULT '',
                env_var TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT ''
             );
             CREATE INDEX IF NOT EXISTS events_ts ON events(ts);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn record(&self, event: NewEvent) -> Result<i64> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::new("audit log lock poisoned"))?;
        conn.execute(
            "INSERT INTO events (ts, kind, severity, child_pid, command, destination, env_var, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                unix_now(),
                event.kind,
                event.severity,
                event.child_pid,
                event.command,
                event.destination,
                event.env_var,
                event.detail,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn recent(&self, limit: usize) -> Result<Vec<Event>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::new("audit log lock poisoned"))?;
        let mut stmt = conn.prepare(
            "SELECT id, ts, kind, severity, child_pid, command, destination, env_var, detail
             FROM events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], row_to_event)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn counts(&self) -> Result<Counts> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::new("audit log lock poisoned"))?;
        let mut stmt = conn.prepare("SELECT kind, COUNT(*) FROM events GROUP BY kind")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut counts = Counts::default();
        for row in rows {
            let (kind, n) = row?;
            let n = n.max(0) as u64;
            match kind.as_str() {
                "mint" => counts.mint = n,
                "swap" => counts.swap = n,
                "scrub" => counts.scrub = n,
                "block" => counts.block = n,
                _ => counts.other += n,
            }
        }
        Ok(counts)
    }
}

#[derive(Debug, Clone)]
pub struct NewEvent {
    pub kind: &'static str,
    pub severity: &'static str,
    pub child_pid: Option<i32>,
    pub command: String,
    pub destination: String,
    pub env_var: String,
    pub detail: String,
}

impl NewEvent {
    pub fn new(kind: &'static str, severity: &'static str) -> Self {
        Self {
            kind,
            severity,
            child_pid: None,
            command: String::new(),
            destination: String::new(),
            env_var: String::new(),
            detail: String::new(),
        }
    }
}

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<Event> {
    Ok(Event {
        id: row.get(0)?,
        ts: row.get(1)?,
        kind: row.get(2)?,
        severity: row.get(3)?,
        child_pid: row.get(4)?,
        command: row.get(5)?,
        destination: row.get(6)?,
        env_var: row.get(7)?,
        detail: row.get(8)?,
    })
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn format_ts(ts: i64) -> String {
    if ts < 0 {
        return format!("{ts}");
    }
    let secs = ts as u64;
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let hh = tod / 3600;
    let mm = (tod % 3600) / 60;
    let ss = tod % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Howard Hinnant's `civil_from_days`, shifted so day 0 is 1970-01-01.
fn civil_from_days(days_since_unix: i64) -> (i32, u32, u32) {
    let z = days_since_unix + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_formats_as_unix_date() {
        assert_eq!(format_ts(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn roundtrip_block_event() {
        let dir = std::env::temp_dir().join(format!("keyalibi-audit-{}-test", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = AuditLog::open(&dir.join("a.db")).unwrap();
        log.record(NewEvent {
            kind: "block",
            severity: "critical",
            child_pid: Some(42),
            command: "pytest".into(),
            destination: "evil.example".into(),
            env_var: "OPENAI_API_KEY".into(),
            detail: "phantom destined for a non-allowlisted host".into(),
        })
        .unwrap();
        let counts = log.counts().unwrap();
        assert_eq!(counts.block, 1);
        let recent = log.recent(10).unwrap();
        assert_eq!(recent[0].env_var, "OPENAI_API_KEY");
        assert_eq!(recent[0].severity, "critical");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
