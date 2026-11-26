// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
// AgentGateway — Transparent MITM proxy for AI request auditing (Rust async core)

mod ca;
mod tls;
mod proxy;
mod detect;
mod attribution;
mod audit;
mod http_mitm;

use clap::Parser;
use std::path::PathBuf;
// Raise the file descriptor limit so many simultaneous tunnels don't hit EMFILE.
fn raise_fd_limit() {
    use libc::{getrlimit, setrlimit, rlimit, RLIMIT_NOFILE};
    let mut rl = rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe {
        if getrlimit(RLIMIT_NOFILE, &mut rl) != 0 {
            return;
        }
        let want = rl.rlim_max.min(65536);
        if want > rl.rlim_cur {
            rl.rlim_cur = want;
            let _ = setrlimit(RLIMIT_NOFILE, &rl);
        }
    }
}

use tokio::signal;

/// AgentGateway — transparent MITM proxy for AI request auditing.
#[derive(Parser, Debug)]
#[command(name = "agentgateway", version, about)]
struct Args {
    /// Listen address
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Listen port (iptables REDIRECT target)
    #[arg(long, default_value_t = 8444)]
    port: u16,

    /// CA certificate path
    #[arg(long, default_value = "certs/ca-cert.pem")]
    ca_cert: PathBuf,

    /// CA key path
    #[arg(long, default_value = "certs/ca-key.pem")]
    ca_key: PathBuf,

    /// Audit SQLite database path
    #[arg(long, default_value = "audit/audit.db")]
    audit_db: PathBuf,

    /// JSONL backup path
    #[arg(long, default_value = "audit/audit.jsonl")]
    audit_jsonl: PathBuf,

    /// Insecure upstream TLS (don't verify upstream certs)
    #[arg(long, default_value_t = true)]
    ssl_insecure: bool,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    // Raise FD limit — each tunnel uses 2 FDs; 1024 default is too low for browsers.
    raise_fd_limit();

    // Initialize audit DB
    audit::audit_init(&args.audit_db, &args.audit_jsonl)
        .expect("failed to init audit DB");

    // Load or generate CA
    let ca = ca::CaCert::load_or_generate(&args.ca_cert, &args.ca_key)
        .expect("failed to load CA");

    // Build TLS certifier
    let certifier = std::sync::Arc::new(tls::Certifier::new(ca));

    // Build upstream connector
    let connector = http_mitm::UpstreamConnector::new(args.ssl_insecure);

    // Start proxy server
    let listener = tokio::net::TcpListener::bind(
        format!("{}:{}", args.host, args.port)
    ).await?;

    eprintln!("═══════════════════════════════════════════════════");
    eprintln!("AgentGateway (Rust) v0.2.0");
    eprintln!("  Proxy:     {}:{}", args.host, args.port);
    eprintln!("  CA cert:   {}", args.ca_cert.display());
    eprintln!("  Audit DB:  {}", args.audit_db.display());
    eprintln!("  JSONL:     {}", args.audit_jsonl.display());
    eprintln!("  Insecure:  {}", args.ssl_insecure);
    eprintln!("═══════════════════════════════════════════════════");

    // Spawn cleanup task (every 10 min, delete >7 days old)
    let db_path = args.audit_db.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
            let _ = audit::cleanup_old_events(&db_path);
        }
    });

    // Spawn the accept loop in a task so we can intercept signals
    let server_handle = tokio::spawn(async move {
        loop {
            let (client_conn, peer_addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[ERROR] accept: {}", e);
                    continue;
                }
            };
            let certifier = certifier.clone();
            let connector = connector.clone();

            tokio::spawn(async move {
                if let Err(e) = proxy::handle_connection(
                    client_conn, peer_addr, certifier, connector,
                ).await {
                    eprintln!("[ERROR] connection from {}: {}", peer_addr, e);
                }
            });
        }
    });

    // Wait for SIGTERM or SIGINT for graceful shutdown (C19)
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let sig = tokio::select! {
        _ = signal::ctrl_c() => "SIGINT",
        _ = sigterm.recv() => "SIGTERM",
    };

    eprintln!("[SHUTDOWN] Received {}, shutting down...", sig);

    // Stop accepting new connections
    server_handle.abort();

    // Flush pending audit events to SQLite
    audit::flush();

    eprintln!("[SHUTDOWN] Done.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ai_request() {
        // AI request with path + body signals
        let body = br#"{"model":"gpt-4","messages":[{"role":"user","content":"hello"}],"max_tokens":100}"#;
        let headers = vec![
            ("Authorization".to_string(), "Bearer sk-xxx".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        let (is_ai, confidence, signals, detail) = detect::detect_ai_request(
            "POST", "/v1/chat/completions", &headers, body,
        );
        assert!(is_ai);
        assert!(confidence >= 3);
        assert!(!signals.is_empty());
        assert_eq!(detail.get("model").and_then(|v| v.as_str()), Some("gpt-4"));
        assert!(detail.get("preview").is_some());
    }

    #[test]
    fn test_detect_non_ai_request() {
        let body = br#"{"foo":"bar"}"#;
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        let (is_ai, _, _, _) = detect::detect_ai_request(
            "GET", "/api/users", &headers, body,
        );
        assert!(!is_ai);
    }

    #[test]
    fn test_audit_log() {
        // Use a temp DB
        let tmp = std::env::temp_dir().join("test_agw_audit.db");
        let tmp_jsonl = std::env::temp_dir().join("test_agw_audit.jsonl");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&tmp_jsonl);
        // Clean up WAL/SHM files
        let _ = std::fs::remove_file(format!("{}-wal", tmp.display()));
        let _ = std::fs::remove_file(format!("{}-shm", tmp.display()));

        audit::audit_init(&tmp, &tmp_jsonl).unwrap();

        let event = audit::AuditEvent {
            event: "ai_request_audited".to_string(),
            decision: "AUDIT".to_string(),
            request_id: "req-test123".to_string(),
            agent_id: "agent-test".to_string(),
            session_id: "session-test".to_string(),
            app_name: "test_app".to_string(),
            method: "POST".to_string(),
            host: "api.openai.com".to_string(),
            port: 443,
            path: "/v1/chat/completions".to_string(),
            model: "gpt-4".to_string(),
            confidence: 5,
            signals: vec!["path_match:/v1/chat/completions".to_string()],
            preview: "hello".to_string(),
            prompt_len: 100,
            stream_mode: false,
            request_headers: None,
            request_body: Some(serde_json::json!({"model": "gpt-4"})),
            response_status: Some(200),
            response_headers: None,
            response_body: Some(serde_json::json!({"choices": []})),
            token_usage: Some(serde_json::json!({"total_tokens": 50})),
            latency_ms: Some(123),
            summary: "test".to_string(),
            source: "test".to_string(),
        };

        audit::audit_log(&event);

        // Give the writer thread a moment to process
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Verify via SQLite
        let conn = rusqlite::Connection::open(&tmp).unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM events WHERE request_id = 'req-test123'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);

        let model: String = conn.query_row(
            "SELECT model FROM events WHERE request_id = 'req-test123'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(model, "gpt-4");

        // Flush and cleanup
        audit::flush();
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&tmp_jsonl);
        let _ = std::fs::remove_file(format!("{}-wal", tmp.display()));
        let _ = std::fs::remove_file(format!("{}-shm", tmp.display()));
        println!("test_audit_log passed!");
    }

    #[test]
    fn test_attribution_lookup() {
        // This test verifies the attribution module doesn't crash
        // with an invalid port (should return all None)
        let (pid, comm, app, agent, session) =
            attribution::lookup_peer(65535, std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
        assert!(pid.is_none());
        assert!(comm.is_none());
        assert!(app.is_none());
        assert!(agent.is_none());
        assert!(session.is_none());
    }

    #[test]
    fn test_extract_sni() {
        // Test SNI extraction from a minimal TLS ClientHello
        // Build a minimal ClientHello with SNI = "example.com"
        let hostname = b"example.com";
        let mut sni_ext = Vec::new();
        // Extension type: 0x0000 (SNI)
        sni_ext.extend_from_slice(&0x0000u16.to_be_bytes());
        let ext_data_len = (5 + hostname.len()) as u16; // list_len(2) + type(1) + name_len(2) + name
        sni_ext.extend_from_slice(&ext_data_len.to_be_bytes());
        let list_len = (3 + hostname.len()) as u16; // type(1) + name_len(2) + name
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0x00); // host_name type
        sni_ext.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(hostname);

        // Build ClientHello body
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session_id_len = 0
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]); // cipher_suites_len=2 + one suite
        hello.push(1); // compression_len=1
        hello.push(0x00); // null compression
        hello.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes()); // extensions_len
        hello.extend_from_slice(&sni_ext);

        // Build handshake header
        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let hl = hello.len();
        hs.push((hl >> 16) as u8);
        hs.push((hl >> 8) as u8);
        hs.push(hl as u8);
        hs.extend_from_slice(&hello);

        // Build TLS record
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);

        let sni = proxy::extract_sni(&record);
        assert_eq!(sni.as_deref(), Some("example.com"));
    }
}
