// SPDX-License-Identifier: Apache-2.0
// HTTP MITM: parse HTTP requests, detect AI calls, audit, forward, capture response.
// Uses hyper for HTTP/1.1 parsing and forwarding.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::server::TlsStream;
use tokio::net::TcpStream;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Body;
use hyper::Request;
use crate::detect::{detect_ai_request, should_mitm_host};
use crate::audit::{audit_log, AuditEvent};
use crate::attribution;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Upstream connector — manages TLS client config and TCP connections.
pub struct UpstreamConnector {
    insecure: bool,
    tls_config: Arc<rustls::ClientConfig>,
}

impl UpstreamConnector {
    pub fn new(insecure: bool) -> Arc<Self> {
        let tls_config = crate::tls::Certifier::client_config_insecure();
        Arc::new(Self { insecure, tls_config })
    }

    /// Connect raw TCP to the upstream address.
    pub async fn connect_tcp(&self, addr: SocketAddr) -> Result<TcpStream, std::io::Error> {
        TcpStream::connect(addr).await
    }

    /// Connect to upstream over TLS.
    pub async fn connect_tls(&self, addr: SocketAddr) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BoxError> {
        let tcp = self.connect_tcp(addr).await?;
        let server_name = rustls::pki_types::ServerName::try_from(addr.ip().to_string())
            .map_err(|e| format!("server name: {e}"))?;
        let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
        let tls = connector.connect(server_name, tcp).await?;
        Ok(tls)
    }
}

/// Process HTTP/1.1 requests over a TLS connection until the client disconnects.
/// For each request:
///   1. Read the full request (method, path, headers, body)
///   2. If AI request: audit + capture response
///   3. Forward to upstream
///   4. Return response to client
pub async fn process_http(
    client: &mut TlsStream<TcpStream>,
    mut upstream: tokio_rustls::client::TlsStream<TcpStream>,
    orig_dst: SocketAddr,
    peer_addr: SocketAddr,
) -> Result<(), BoxError> {
    let host = orig_dst.ip().to_string();
    let port = orig_dst.port();

    let mut buf = vec![0u8; 65536];
    let mut client_read_buf: Vec<u8> = Vec::new();
    let _ = client_read_buf;

    loop {
        // Read HTTP request from client
        let req_data = match read_http_request(client).await? {
            Some(data) => data,
            None => break, // client closed
        };

        // Parse request line + headers
        let (method, path, headers, header_len) = match parse_request_head(&req_data) {
            Some(r) => r,
            None => {
                // Can't parse — forward as-is and hope for the best
                upstream.write_all(&req_data).await?;
                continue;
            }
        };

        let body = if req_data.len() > header_len {
            req_data[header_len..].to_vec()
        } else {
            Vec::new()
        };

        // Check if this is an AI request
        let (is_ai, confidence, signals, detail) = detect_ai_request(
            &method, &path, &headers, &body,
        );

        let request_id = if is_ai {
            let req_id = format!("req-{}", uuid_v4());

            // Process attribution
            let peer_port = peer_addr.port();
            let (agent_pid, agent_comm, app_name, agent_id, session_id) =
                attribution::lookup_peer(peer_port);

            let request_body_json: Option<serde_json::Value> = serde_json::from_slice(&body).ok();

            let event = AuditEvent {
                event: "ai_request_audited".to_string(),
                decision: "AUDIT".to_string(),
                request_id: req_id.clone(),
                agent_id: agent_id.unwrap_or_default(),
                session_id: session_id.unwrap_or_default(),
                app_name: app_name.unwrap_or_default(),
                method: method.clone(),
                host: host.clone(),
                port: port as i64,
                path: path.clone(),
                model: detail.get("model").map(|v| v.to_string()).unwrap_or_default(),
                confidence: confidence as i64,
                signals: signals.clone(),
                preview: detail.get("preview").map(|v| v.to_string()).unwrap_or_default(),
                prompt_len: detail.get("prompt_len").and_then(|v| v.as_u64()).unwrap_or(0) as i64,
                stream_mode: detail.get("stream_mode").and_then(|v| v.as_bool()).unwrap_or(false),
                request_headers: headers_to_json(&headers),
                request_body: request_body_json,
                response_status: None,
                response_headers: None,
                response_body: None,
                token_usage: None,
                latency_ms: None,
                summary: format!("AI request audited & forwarded: {} {}{} model={}", method, host, path, detail.get("model").map(|m| m.as_str().unwrap_or("")).unwrap_or("")),
                source: "rust_proxy".to_string(),
            };

            audit_log(&event);
            Some((req_id, Instant::now()))
        } else {
            None
        };

        // Forward request to upstream
        upstream.write_all(&req_data).await?;
        upstream.flush().await?;

        // Read response from upstream and forward to client
        let resp_data = read_http_response(&mut upstream).await?;

        // If AI request, capture response metadata
        if let Some((req_id, t0)) = &request_id {
            let latency_ms = t0.elapsed().as_millis() as i64;

            let (status, resp_headers, resp_body) = parse_response_head(&resp_data).unwrap_or((0, Vec::new(), Vec::new()));

            let resp_body_json: Option<serde_json::Value> = serde_json::from_slice(&resp_body).ok();

            // Extract token usage
            let token_usage = resp_body_json.as_ref().and_then(|j| j.get("usage")).map(|u| u.clone());

            let event = AuditEvent {
                event: "ai_response".to_string(),
                decision: String::new(),
                request_id: req_id.clone(),
                agent_id: String::new(),
                session_id: String::new(),
                app_name: String::new(),
                method: String::new(),
                host: String::new(),
                port: 0,
                path: String::new(),
                model: String::new(),
                confidence: 0,
                signals: Vec::new(),
                preview: String::new(),
                prompt_len: 0,
                stream_mode: false,
                request_headers: None,
                request_body: None,
                response_status: Some(status as i64),
                response_headers: headers_to_json(&resp_headers),
                response_body: resp_body_json,
                token_usage,
                latency_ms: Some(latency_ms),
                summary: format!("Response {} ({}ms)", status, latency_ms),
                source: "rust_proxy".to_string(),
            };

            audit_log(&event);
        }

        // Forward response to client
        client.write_all(&resp_data).await?;
        client.flush().await?;
    }

    Ok(())
}

/// Read a complete HTTP request from a TLS stream.
/// Returns the raw bytes including request line, headers, and body.
async fn read_http_request<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, std::io::Error> {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];

    // Read until we find \r\n\r\n (end of headers)
    loop {
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            // Found end of headers at pos+4
            // Check Content-Length to read body
            let header_str = String::from_utf8_lossy(&buf[..pos]);
            let content_length = parse_content_length(&header_str);
            let header_end = pos + 4;
            if let Some(cl) = content_length {
                while buf.len() < header_end + cl {
                    let n = reader.read(&mut tmp).await?;
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
            }
            // Note: chunked transfer encoding not fully handled here.
            // For simplicity, we read what's available. AI API requests
            // typically use Content-Length.
            break;
        }
    }

    Ok(Some(buf))
}

/// Read a complete HTTP response from a TLS stream.
async fn read_http_response<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];

    // Read until we find \r\n\r\n
    loop {
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            let header_end = pos + 4;
            let header_str = String::from_utf8_lossy(&buf[..pos]);

            // Check for chunked encoding
            let is_chunked = header_str.to_lowercase().contains("transfer-encoding: chunked");
            let content_length = parse_content_length(&header_str);

            if is_chunked {
                // Read until we see "0\r\n\r\n" (end of chunked)
                loop {
                    if buf.windows(5).any(|w| w == b"0\r\n\r\n") {
                        break;
                    }
                    let n = reader.read(&mut tmp).await?;
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
            } else if let Some(cl) = content_length {
                while buf.len() < header_end + cl {
                    let n = reader.read(&mut tmp).await?;
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
            } else {
                // No Content-Length, no chunked — read until EOF
                loop {
                    let n = reader.read(&mut tmp).await?;
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
            }
            break;
        }
    }

    Ok(buf)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(header_str: &str) -> Option<usize> {
    for line in header_str.lines() {
        if line.to_lowercase().starts_with("content-length:") {
            let val = line[15..].trim();
            return val.parse().ok();
        }
    }
    None
}

/// Parse the request head (method, path, headers) from raw bytes.
/// Returns (method, path, headers, header_len_including_blank_line).
fn parse_request_head(data: &[u8]) -> Option<(String, String, Vec<(String, String)>, usize)> {
    let pos = find_header_end(data)?;
    let header_str = String::from_utf8_lossy(&data[..pos]);
    let mut lines = header_str.lines();

    let request_line = lines.next()?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let method = parts[0].to_string();
    let path = parts[1].to_string();

    let mut headers = Vec::new();
    for line in lines {
        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.push((name, value));
        }
    }

    Some((method, path, headers, pos + 4))
}

/// Parse the response head from raw bytes.
/// Returns (status_code, headers, body).
fn parse_response_head(data: &[u8]) -> Option<(u16, Vec<(String, String)>, Vec<u8>)> {
    let pos = find_header_end(data)?;
    let header_str = String::from_utf8_lossy(&data[..pos]);
    let mut lines = header_str.lines();

    let status_line = lines.next()?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let status: u16 = parts[1].parse().ok()?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.push((name, value));
        }
    }

    let body = if data.len() > pos + 4 {
        data[pos + 4..].to_vec()
    } else {
        Vec::new()
    };

    Some((status, headers, body))
}

fn headers_to_json(headers: &[(String, String)]) -> Option<serde_json::Value> {
    if headers.is_empty() {
        return None;
    }
    let mut map = serde_json::Map::new();
    for (k, v) in headers {
        // Redact sensitive headers
        let kl = k.to_lowercase();
        if matches!(kl.as_str(), "authorization" | "x-api-key" | "cookie" | "x-goog-api-key") {
            map.insert(k.clone(), serde_json::Value::String("[REDACTED]".to_string()));
        } else {
            map.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
    }
    Some(serde_json::Value::Object(map))
}

/// Simple UUID v4 generator (no external dep needed for this).
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:016x}{:016x}", now, std::process::id() as u128)
}
