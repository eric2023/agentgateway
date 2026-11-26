// SPDX-License-Identifier: Apache-2.0
// HTTP MITM: parse HTTP requests, detect AI calls, audit, forward, capture response.
// Manual HTTP/1.1 byte-level parsing (no hyper dependency).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::server::TlsStream;
use tokio::net::TcpStream;
use crate::detect::detect_ai_request;
use crate::audit::{audit_log, AuditEvent};
use crate::attribution;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Upstream connector — manages TLS client config and TCP connections.
pub struct UpstreamConnector {
    tls_config: Arc<rustls::ClientConfig>,
}

impl UpstreamConnector {
    pub fn new(insecure: bool) -> Arc<Self> {
        let tls_config = if insecure {
            crate::tls::Certifier::client_config_insecure()
        } else {
            crate::tls::Certifier::client_config_secure()
        };
        Arc::new(Self { tls_config })
    }

    /// Connect raw TCP to the upstream address (with 10s timeout).
    pub async fn connect_tcp(&self, addr: SocketAddr) -> Result<TcpStream, std::io::Error> {
        match tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(addr),
        ).await {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upstream TCP connect timeout",
            )),
        }
    }

    /// Connect to upstream over TLS, using SNI hostname as ServerName.
    pub async fn connect_tls(
        &self,
        addr: SocketAddr,
        sni: Option<&str>,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BoxError> {
        let tcp = self.connect_tcp(addr).await?;
        // Use SNI hostname as ServerName; fall back to IP if no SNI
        let server_name = match sni {
            Some(h) => rustls::pki_types::ServerName::try_from(h.to_string())
                .map_err(|e| format!("server name: {e}"))?,
            None => rustls::pki_types::ServerName::try_from(addr.ip().to_string())
                .map_err(|e| format!("server name: {e}"))?,
        };
        let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
        let tls = tokio::time::timeout(
            Duration::from_secs(10),
            connector.connect(server_name, tcp),
        )
        .await
        .map_err(|_| -> BoxError { "upstream TLS handshake timeout".into() })??;
        Ok(tls)
    }
}

/// Process HTTP/1.1 requests over a TLS connection with keep-alive.
/// Loops to handle multiple sequential requests on the same connection
/// (request→response→request→response), which keeps keep-alive working
/// while still disabling pipelining (pipelining sends the next request
/// before the prior response arrives).
/// For each request:
///   1. Read the full request (method, path, headers, body)
///   2. If AI request: audit + capture response
///   3. Forward to upstream
///   4. Return response to client
///   5. Loop and wait for the next request (keep-alive)
pub async fn process_http(
    client: &mut TlsStream<TcpStream>,
    mut upstream: tokio_rustls::client::TlsStream<TcpStream>,
    orig_dst: SocketAddr,
    peer_addr: SocketAddr,
    sni: Option<&str>,
) -> Result<(), BoxError> {
    // host and port are computed outside the loop (initialized from SNI/IP).
    // host is updated per-request from the HTTP Host header when available (NEW-9).
    let mut host = sni.map(|s| s.to_string()).unwrap_or_else(|| orig_dst.ip().to_string());
    let port = orig_dst.port();

    loop {
        // Read HTTP request from client (with 30s timeout).
        // A read timeout or client close ends the keep-alive loop gracefully.
        let req_data = match tokio::time::timeout(
            Duration::from_secs(30),
            read_http_request(client),
        ).await {
            Ok(Ok(Some(data))) => data,
            Ok(Ok(None)) => return Ok(()), // client closed
            Ok(Err(e)) => return Err(Box::new(e)),
            Err(_) => return Ok(()), // read timeout — close connection gracefully
        };

        // Parse request line + headers
        let (method, path, headers, header_len) = match parse_request_head(&req_data) {
            Some(r) => r,
            None => {
                // Can't parse — forward as-is and hope for the best
                upstream.write_all(&req_data).await?;
                return Ok(());
            }
        };

        // Prefer the HTTP Host header over SNI/IP for the audit host (NEW-9).
        // Strip the port number if present.
        if let Some((_, h)) = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")) {
            host = h.split(':').next().unwrap_or(h).to_string();
        }

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
            let (_agent_pid, _agent_comm, app_name, agent_id, session_id) =
                attribution::lookup_peer(peer_port, peer_addr.ip());

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

        // Stream response (replaces read_http_response + client.write_all)
        // Returns true if the response signaled Connection: close.
        let resp_close = if let Some((req_id, t0)) = &request_id {
            stream_http_response(&mut upstream, client, req_id, *t0).await?
        } else {
            stream_response_simple(&mut upstream, client).await?
        };
        // Honor Connection: close on either the request or the response:
        // break the keep-alive loop so the connection closes cleanly instead
        // of waiting for a next request that will never come.
        let req_header_str = String::from_utf8_lossy(&req_data[..header_len]);
        if resp_close || is_connection_close(&req_header_str) {
            return Ok(());
        }

        // Loop continues — wait for the next request on the same connection (keep-alive).
    }
}

/// Read a complete HTTP request from a TLS stream.
/// Returns the raw bytes including request line, headers, and body.
/// Handles Content-Length and chunked transfer encoding.
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
            let header_str = String::from_utf8_lossy(&buf[..pos]);
            let header_end = pos + 4;
            let content_length = parse_content_length(&header_str);
            let is_chunked = is_chunked(&header_str);

            if is_chunked {
                // Read until chunked end marker (0\r\n\r\n)
                loop {
                    if find_chunked_end(&buf, header_end).is_some() {
                        break;
                    }
                    let n = reader.read(&mut tmp).await?;
                    if n == 0 { break; }
                    buf.extend_from_slice(&tmp[..n]);
                }
            } else if let Some(cl) = content_length {
                while buf.len() < header_end + cl {
                    let n = reader.read(&mut tmp).await?;
                    if n == 0 { break; }
                    buf.extend_from_slice(&tmp[..n]);
                }
            }
            // No Content-Length and not chunked: body is empty (GET/DELETE etc.)
            break;
        }
    }

    Ok(Some(buf))
}
/// Stream HTTP response from upstream to client: read headers, then pipe body.
/// Records response audit event with status, headers, and body preview (first 4KB).
async fn stream_http_response(
    upstream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    client: &mut TlsStream<TcpStream>,
    req_id: &str,
    t0: Instant,
) -> Result<bool, BoxError> {
    // 1. Read response headers (up to \r\n\r\n), with 60s timeout
    let mut header_buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = tokio::time::timeout(
            Duration::from_secs(60),
            upstream.read(&mut tmp),
        ).await
            .map_err(|_| -> BoxError { "response header read timeout".into() })??;
        if n == 0 {
            if !header_buf.is_empty() {
                client.write_all(&header_buf).await?;
                client.flush().await?;
            }
            return Ok(false);
        }
        header_buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&header_buf) {
            let hdr_end = pos + 4;
            client.write_all(&header_buf[..hdr_end]).await?;
            client.flush().await?;
            break pos + 4;
        }
    };

    // 2. Parse response status + headers for audit
    let header_str = String::from_utf8_lossy(&header_buf[..header_end - 4]);
    let (status, resp_headers, _) = parse_response_head(&header_buf).unwrap_or((0, Vec::new(), Vec::new()));

    // 3. Stream body to client, capturing first 4KB for audit preview
    let mut body_preview = Vec::with_capacity(4096);
    let body_start = &header_buf[header_end..];

    if !body_start.is_empty() {
        client.write_all(body_start).await?;
        if body_preview.len() < 4096 {
            let take = std::cmp::min(4096 - body_preview.len(), body_start.len());
            body_preview.extend_from_slice(&body_start[..take]);
        }
    }
    client.flush().await?;

    // Stream remaining body with 300s idle timeout
    let is_chunked = is_chunked(&header_str);
    let content_length = parse_content_length(&header_str);
    let mut total_body: u64 = body_start.len() as u64;
    // For chunked responses, accumulate body bytes to detect the 0\r\n\r\n terminator.
    // Content-Length responses just count bytes; connection-close responses pipe to EOF.
    let mut body_buf = if is_chunked {
        let mut v = Vec::new();
        v.extend_from_slice(body_start);
        v
    } else {
        Vec::new()
    };
    loop {
        // Check termination BEFORE reading more (handles bodies already complete
        // in the header buffer, and stops as soon as the terminator is fully read).
        if is_chunked {
            if find_chunked_end(&body_buf, 0).is_some() {
                break;
            }
        } else if let Some(cl) = content_length {
            if total_body >= cl as u64 {
                break;
            }
        }

        let n = tokio::time::timeout(
            Duration::from_secs(300),
            upstream.read(&mut tmp),
        ).await
            .map_err(|_| -> BoxError { "response body read timeout".into() })??;
        if n == 0 { break; }
        client.write_all(&tmp[..n]).await?;
        client.flush().await?;
        if body_preview.len() < 4096 {
            let take = std::cmp::min(4096 - body_preview.len(), n);
            body_preview.extend_from_slice(&tmp[..take]);
        }
        if is_chunked {
            body_buf.extend_from_slice(&tmp[..n]);
        }
        total_body += n as u64;
    }

    // 4. Record audit event
    let latency_ms = t0.elapsed().as_millis() as i64;
    let resp_body_json: Option<serde_json::Value> =
        if body_preview.len() < 4096 {
            serde_json::from_slice(&body_preview).ok()
        } else {
            None
        };
    let token_usage = resp_body_json.as_ref()
        .and_then(|j| j.get("usage"))
        .map(|u| u.clone());

    let event = AuditEvent {
        event: "ai_response".to_string(),
        decision: String::new(),
        request_id: req_id.to_string(),
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
        summary: format!("Response {} ({}ms, {}B)", status, latency_ms, total_body),
        source: "rust_proxy".to_string(),
    };
    audit_log(&event);

    let resp_close = is_connection_close(&header_str);
    Ok(resp_close)
}

/// Stream response for non-AI requests: parse headers, then stream the body
/// with proper termination (chunked or Content-Length) so the keep-alive loop
/// can reuse the upstream connection. No audit recording.
async fn stream_response_simple(
    upstream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    client: &mut TlsStream<TcpStream>,
) -> Result<bool, BoxError> {
    // 1. Read response headers (up to \r\n\r\n), with 60s timeout
    let mut header_buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = tokio::time::timeout(
            Duration::from_secs(60),
            upstream.read(&mut tmp),
        ).await
            .map_err(|_| -> BoxError { "response header read timeout".into() })??;
        if n == 0 {
            if !header_buf.is_empty() {
                client.write_all(&header_buf).await?;
                client.flush().await?;
            }
            return Ok(false);
        }
        header_buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&header_buf) {
            let hdr_end = pos + 4;
            client.write_all(&header_buf[..hdr_end]).await?;
            client.flush().await?;
            break hdr_end;
        }
    };

    // 2. Determine body framing
    let header_str = String::from_utf8_lossy(&header_buf[..header_end - 4]);
    let is_chunked = is_chunked(&header_str);
    let content_length = parse_content_length(&header_str);

    // 3. Forward any body bytes that arrived with the headers
    let body_start = &header_buf[header_end..];
    if !body_start.is_empty() {
        client.write_all(body_start).await?;
        client.flush().await?;
    }
    let mut total_body: u64 = body_start.len() as u64;
    let mut body_buf = if is_chunked {
        let mut v = Vec::new();
        v.extend_from_slice(body_start);
        v
    } else {
        Vec::new()
    };

    // 4. Stream body with 300s idle timeout, terminating on chunked end
    //    or Content-Length exhaustion (keeps the upstream reusable).
    loop {
        if is_chunked {
            if find_chunked_end(&body_buf, 0).is_some() {
                break;
            }
        } else if let Some(cl) = content_length {
            if total_body >= cl as u64 {
                break;
            }
        }

        let n = tokio::time::timeout(
            Duration::from_secs(300),
            upstream.read(&mut tmp),
        ).await
            .map_err(|_| -> BoxError { "response body read timeout".into() })??;
        if n == 0 { break; }
        client.write_all(&tmp[..n]).await?;
        client.flush().await?;
        if is_chunked {
            body_buf.extend_from_slice(&tmp[..n]);
        }
        total_body += n as u64;
    }

    let resp_close = is_connection_close(&header_str);
    Ok(resp_close)
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

fn is_chunked(header_str: &str) -> bool {
    header_str.to_lowercase().contains("transfer-encoding: chunked")
}

fn is_connection_close(header_str: &str) -> bool {
    header_str.to_lowercase().contains("connection: close")
}

/// Find the end of a chunked-encoded body by parsing chunk boundaries.
/// Returns the byte offset after the final "0\r\n\r\n".
fn find_chunked_end(buf: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    loop {
        // Find the end of the chunk size line
        let line_end = buf[pos..].windows(2).position(|w| w == b"\r\n")?;
        let line_end_abs = pos + line_end;
        let size_str = std::str::from_utf8(&buf[pos..line_end_abs]).ok()?;
        let chunk_size = usize::from_str_radix(
            size_str.split(';').next()?.trim(), 16
        ).ok()?;
        pos = line_end_abs + 2; // skip chunk size line + \r\n

        if chunk_size == 0 {
            // Last chunk — expect \r\n (or trailer headers + \r\n\r\n)
            if pos + 2 <= buf.len() && &buf[pos..pos + 2] == b"\r\n" {
                return Some(pos + 2);
            }
            // Look for \r\n\r\n (trailer headers)
            if let Some(trailer_end) = buf[pos..].windows(4).position(|w| w == b"\r\n\r\n") {
                return Some(pos + trailer_end + 4);
            }
            return None; // trailer not yet received
        }

        pos += chunk_size + 2; // chunk data + trailing \r\n
        if pos > buf.len() { return None; }
    }
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

/// UUID v4 generator using /dev/urandom for true randomness.
fn uuid_v4() -> String {
    use std::io::Read;
    let mut buf = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            // Set version 4 and variant bits
            buf[6] = (buf[6] & 0x0f) | 0x40;
            buf[8] = (buf[8] & 0x3f) | 0x80;
            return format!(
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                buf[0], buf[1], buf[2], buf[3],
                buf[4], buf[5], buf[6], buf[7],
                buf[8], buf[9], buf[10], buf[11],
                buf[12], buf[13], buf[14], buf[15]
            );
        }
    }
    // Fallback: atomic counter + nanosecond timestamp
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("req-fallback-{:016x}-{:016x}", now, c)
}
