// SPDX-License-Identifier: Apache-2.0
// Audit logging — SQLite WAL + JSONL dual-write.
// Uses a dedicated writer thread (mpsc channel) to avoid blocking the async runtime (C04).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender, Receiver, TrySendError};
use std::sync::{Mutex, LazyLock};
use rusqlite::Connection;
use serde_json::Value;

const MAX_BODY_SIZE: usize = 64 * 1024; // 64KB

#[derive(Clone)]
pub struct AuditEvent {
    pub event: String,
    pub decision: String,
    pub request_id: String,
    pub agent_id: String,
    pub session_id: String,
    pub app_name: String,
    pub method: String,
    pub host: String,
    pub port: i64,
    pub path: String,
    pub model: String,
    pub confidence: i64,
    pub signals: Vec<String>,
    pub preview: String,
    pub prompt_len: i64,
    pub stream_mode: bool,
    pub request_headers: Option<Value>,
    pub request_body: Option<Value>,
    pub response_status: Option<i64>,
    pub response_headers: Option<Value>,
    pub response_body: Option<Value>,
    pub token_usage: Option<Value>,
    pub latency_ms: Option<i64>,
    pub summary: String,
    pub source: String,
}

/// Channel sender to the dedicated SQLite writer thread.
static TX: LazyLock<Mutex<Option<SyncSender<AuditEvent>>>> = LazyLock::new(|| Mutex::new(None));

/// Writer thread handle, saved for flush() to wait on.
static WRITER_HANDLE: LazyLock<Mutex<Option<std::thread::JoinHandle<()>>>> = LazyLock::new(|| Mutex::new(None));

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    ts_unix     REAL NOT NULL,
    event       TEXT NOT NULL,
    decision    TEXT,
    request_id  TEXT,
    agent_id    TEXT,
    session_id  TEXT,
    app_name    TEXT,
    method      TEXT,
    host        TEXT,
    port        INTEGER,
    path        TEXT,
    model       TEXT,
    confidence  INTEGER,
    signals     TEXT,
    preview     TEXT,
    prompt_len  INTEGER,
    stream_mode INTEGER,
    request_headers  TEXT,
    request_body     TEXT,
    response_status  INTEGER,
    response_headers TEXT,
    response_body    TEXT,
    token_usage TEXT,
    latency_ms  INTEGER,
    summary     TEXT,
    source      TEXT
);
CREATE INDEX IF NOT EXISTS idx_ts     ON events(ts_unix DESC);
CREATE INDEX IF NOT EXISTS idx_req_id ON events(request_id);
CREATE INDEX IF NOT EXISTS idx_agent  ON events(agent_id);
CREATE INDEX IF NOT EXISTS idx_event  ON events(event);
";

/// Initialize the audit database, JSONL backup file, and writer thread.
pub fn audit_init(db_path: &Path, jsonl_path: &Path) -> Result<(), String> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
    }
    if let Some(parent) = jsonl_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
    }

    let conn = Connection::open(db_path).map_err(|e| format!("open db: {e}"))?;
    conn.execute_batch("PRAGMA journal_mode=WAL;").map_err(|e| format!("wal: {e}"))?;
    conn.execute_batch("PRAGMA synchronous=NORMAL;").map_err(|e| format!("sync: {e}"))?;
    conn.execute_batch(SCHEMA).map_err(|e| format!("schema: {e}"))?;

    // Clean old events: >7 days
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as f64 - 7.0 * 86400.0;
    conn.execute("DELETE FROM events WHERE ts_unix < ?1", [cutoff])
        .map_err(|e| format!("cleanup: {e}"))?;

    // Keep last 50000 rows
    conn.execute(
        "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 50000)",
        [],
    ).map_err(|e| format!("limit: {e}"))?;

    eprintln!("[AUDIT] SQLite: {}", db_path.display());

    // Spawn dedicated writer thread
    let (tx, rx): (SyncSender<AuditEvent>, Receiver<AuditEvent>) = mpsc::sync_channel(1000);
    let jsonl_path = PathBuf::from(jsonl_path);

    let handle = std::thread::spawn(move || {
        writer_thread(conn, rx, &jsonl_path);
    });

    {
        let mut tx_guard = TX.lock().unwrap();
        *tx_guard = Some(tx);
    }
    {
        let mut h_guard = WRITER_HANDLE.lock().unwrap();
        *h_guard = Some(handle);
    }

    Ok(())
}

/// Dedicated writer thread: receives events via channel, writes to SQLite + JSONL.
fn writer_thread(conn: Connection, rx: Receiver<AuditEvent>, jsonl_path: &Path) {
    // Open JSONL file once and keep a BufWriter for the lifetime of the thread.
    let mut jsonl = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(jsonl_path)
        .map(std::io::BufWriter::new)
        .ok();

    for event in rx {
        let now = chrono_iso();
        let ts_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let signals_json = serde_json::to_string(&event.signals).unwrap_or_default();
        let req_headers = event.request_headers.as_ref().map(truncate_json);
        let req_body = event.request_body.as_ref().map(truncate_json);
        let resp_headers = event.response_headers.as_ref().map(truncate_json);
        let resp_body = event.response_body.as_ref().map(truncate_json);
        let token_usage = event.token_usage.as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());

        // SQLite insert
        let _ = conn.execute(
            "INSERT INTO events (
                ts, ts_unix, event, decision, request_id, agent_id, session_id,
                app_name, method, host, port, path, model, confidence, signals,
                preview, prompt_len, stream_mode, request_headers, request_body,
                response_status, response_headers, response_body,
                token_usage, latency_ms, summary, source
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rusqlite::params![
                &now, ts_unix, &event.event, &event.decision,
                &event.request_id, &event.agent_id, &event.session_id,
                &event.app_name, &event.method, &event.host, event.port,
                &event.path, &event.model, event.confidence, &signals_json,
                &event.preview, event.prompt_len,
                if event.stream_mode { 1 } else { 0 },
                req_headers.as_deref(), req_body.as_deref(),
                event.response_status,
                resp_headers.as_deref(), resp_body.as_deref(),
                token_usage.as_deref(), event.latency_ms,
                &event.summary, &event.source,
            ],
        );

        // JSONL backup
        if let Some(writer) = &mut jsonl {
            let json_obj = serde_json::json!({
                "ts": now,
                "ts_unix": ts_unix,
                "event": event.event,
                "decision": event.decision,
                "request_id": event.request_id,
                "agent_id": event.agent_id,
                "session_id": event.session_id,
                "app_name": event.app_name,
                "method": event.method,
                "host": event.host,
                "port": event.port,
                "path": event.path,
                "model": event.model,
                "confidence": event.confidence,
                "signals": event.signals,
                "preview": event.preview,
                "prompt_len": event.prompt_len,
                "stream_mode": event.stream_mode,
                "request_headers": event.request_headers,
                "request_body": event.request_body,
                "response_status": event.response_status,
                "response_headers": event.response_headers,
                "response_body": event.response_body,
                "token_usage": event.token_usage,
                "latency_ms": event.latency_ms,
                "summary": event.summary,
                "source": event.source,
            });
            let line = serde_json::to_string(&json_obj).unwrap_or_default();
            let _ = writeln!(writer, "{}", line);
        }
    }

    // Flush remaining buffered JSONL data on shutdown
    if let Some(mut writer) = jsonl {
        let _ = writer.flush();
    }
}

/// Write an audit event to the writer thread via channel (non-blocking).
pub fn audit_log(event: &AuditEvent) {
    let tx_guard = TX.lock().unwrap();
    if let Some(sender) = tx_guard.as_ref() {
        match sender.try_send(event.clone()) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                static DROPPED: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let n = DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if n % 100 == 0 {
                    eprintln!("[AUDIT] WARNING: {} events dropped (channel full)", n + 1);
                }
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

/// Flush pending audit events (drop sender to close channel, letting writer drain).
/// Called during graceful shutdown.
pub fn flush() {
    // Drop sender to close channel
    {
        let mut tx_guard = TX.lock().unwrap();
        *tx_guard = None;
    }

    // Wait for writer thread to finish (with 5s timeout)
    let mut h_guard = WRITER_HANDLE.lock().unwrap();
    if let Some(handle) = h_guard.take() {
        let start = std::time::Instant::now();
        while !handle.is_finished() && start.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if !handle.is_finished() {
            eprintln!("[AUDIT] WARNING: writer thread did not finish in 5s");
        }
    }
}

/// Delete events older than 7 days or beyond 50000 rows.
pub fn cleanup_old_events(db_path: &Path) -> Result<(), String> {
    let conn = Connection::open(db_path).map_err(|e| format!("open: {e}"))?;
    conn.execute_batch("PRAGMA journal_mode=WAL;").map_err(|e| format!("wal: {e}"))?;
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as f64 - 7.0 * 86400.0;
    conn.execute("DELETE FROM events WHERE ts_unix < ?1", [cutoff])
        .map_err(|e| format!("cleanup: {e}"))?;
    conn.execute(
        "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 50000)",
        [],
    ).map_err(|e| format!("limit: {e}"))?;
    Ok(())
}

/// Truncate a JSON value to MAX_BODY_SIZE, respecting UTF-8 character boundaries (C18).
fn truncate_json(v: &Value) -> String {
    let s = serde_json::to_string(v).unwrap_or_default();
    if s.len() <= MAX_BODY_SIZE {
        return s;
    }
    // Find the largest valid UTF-8 boundary <= MAX_BODY_SIZE
    let mut end = MAX_BODY_SIZE;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

fn chrono_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let secs = now.as_secs();
    let millis = now.subsec_millis();

    // Convert to UTC datetime
    let (year, month, day, hour, min, sec) = unix_to_ymd(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}+00:00",
            year, month, day, hour, min, sec, millis)
}

fn unix_to_ymd(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = (secs / 86400) as i64;
    let rem = (secs % 86400) as u32;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    // Days since 1970-01-01 → YMD
    let mut y = 1970i64;
    let mut d = days;
    loop {
        let dy = if is_leap(y) { 366 } else { 365 };
        if d < dy {
            break;
        }
        d -= dy;
        y += 1;
    }
    let months = [31, if is_leap(y) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut m = 0u32;
    for (i, &mdays) in months.iter().enumerate() {
        if d < mdays as i64 {
            m = (i + 1) as u32;
            break;
        }
        d -= mdays as i64;
    }
    let day = (d + 1) as u32;
    (y as u32, m, day, hour, min, sec)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}
