# 方案 C 缺陷修复计划（第二轮）

> 基于 2026-11-26 代码审查发现的 10 个新缺陷
> 创建时间：2026-11-26
> 预计总工期：1.5 天

---

## 缺陷来源

C01-C20 原始缺陷已全部修复并验证通过（commit `c448c0f`，cargo build + 5/5 test pass）。
二次代码审查发现 10 个新缺陷，按严重性分 3 个阶段修复。

## 修复阶段划分

```
阶段 R4：P0 严重修复（阻断核心功能）           ← 0.5 天
  R4.1 NEW-2: SSE 流式响应边读边转发
  R4.2 NEW-1: peek_buf 增大到 16384 字节
  └── 验证：cargo build + cargo test + 流式请求端到端

阶段 R5：P1 重要修复（影响可靠性）             ← 0.5 天
  R5.1 NEW-5: 恢复 keep-alive 循环（顺序处理，不并发）
  R5.2 NEW-9: audit host 优先用 Host header
  └── 验证：cargo build + cargo test + keep-alive 请求

阶段 R6：P2 一般修复（影响可维护性）           ← 0.5 天
  R6.1 NEW-3: audit channel 改 bounded
  R6.2 NEW-4: blind_tunnel 加 idle 超时
  R6.3 NEW-6: --ssl-insecure 参数实现或删除
  R6.4 NEW-7: flush() 等待 writer thread 退出
  R6.5 NEW-8: do_foreground() 改用 wait_for_port
  R6.6 NEW-10: ca.rs 缓存 CA Certificate 对象
  └── 验证：cargo build 无 warning + cargo test
```

---

## 阶段 R4：P0 严重修复

### R4.1 NEW-2 — SSE 流式响应边读边转发

**根因**：`read_http_response()` 读取完整响应后才 `client.write_all(&resp_data)`。对 `text/event-stream` 或 chunked 流式响应，代理阻塞到上游关闭连接，客户端长时间收不到数据。

**修复方案**：将 `process_http()` 改为 streaming 模式——请求完整读取并转发后，响应改为**边读边转发**，不再缓冲完整响应。审计改为只记录已解析的响应头 + 前若干字节 body 预览。

**改动文件**：`src/http_mitm.rs`

**核心改动**：

1. 删除 `read_http_response()`，改为 `stream_http_response()`
2. `stream_http_response()` 先读响应头（到 `\r\n\r\n`），解析 status + headers，写入审计
3. body 部分用 `tokio::io::copy` 边读边转发（chunked 逐 chunk 透传，CL 按 CL 长度透传，Connection: close 读到 EOF）
4. 审计事件只记录 status + response_headers + body 前 4KB 预览（不保存完整 body）

```rust
/// Stream HTTP response from upstream to client: read headers, then pipe body.
/// Records response audit event with status, headers, and body preview (first 4KB).
async fn stream_http_response(
    upstream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    client: &mut TlsStream<TcpStream>,
    req_id: &str,
    t0: Instant,
    host: &str,
) -> Result<(), BoxError> {
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
            // Upstream closed before headers — forward what we have
            if !header_buf.is_empty() {
                client.write_all(&header_buf).await?;
                client.flush().await?;
            }
            return Ok(());
        }
        header_buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&header_buf) {
            // Forward headers to client immediately
            client.write_all(&header_buf).await?;
            client.flush().await?;
            break pos + 4; // start of body
        }
    };

    // 2. Parse response status + headers for audit
    let header_str = String::from_utf8_lossy(&header_buf[..header_end - 4]);
    let (status, resp_headers, _) = parse_response_head(&header_buf).unwrap_or((0, Vec::new(), Vec::new()));

    // 3. Determine body framing
    let is_chunked = is_chunked(&header_str);
    let content_length = parse_content_length(&header_str);
    let is_close = is_connection_close(&header_str);

    // 4. Stream body to client, capturing first 4KB for audit preview
    let mut body_preview = Vec::with_capacity(4096);
    let body_start = &header_buf[header_end..];

    // Forward any body bytes already read (part of header_buf beyond \r\n\r\n)
    if !body_start.is_empty() {
        client.write_all(body_start).await?;
        if body_preview.len() < 4096 {
            let take = std::cmp::min(4096 - body_preview.len(), body_start.len());
            body_preview.extend_from_slice(&body_start[..take]);
        }
    }
    client.flush().await?;

    // Stream remaining body
    let mut total_body: u64 = body_start.len() as u64;
    loop {
        let n = tokio::time::timeout(
            Duration::from_secs(300), // 5 min idle timeout for streaming
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
        total_body += n as u64;

        // If Content-Length, check if we've read enough
        if let Some(cl) = content_length {
            if total_body >= cl as u64 { break; }
        }
    }

    // 5. Record audit event
    let latency_ms = t0.elapsed().as_millis() as i64;
    let resp_body_json: Option<serde_json::Value> =
        if body_preview.len() < 4096 {
            serde_json::from_slice(&body_preview).ok()
        } else {
            None // truncated, don't parse
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

    Ok(())
}
```

**`process_http()` 尾部改动**：

```rust
    // Forward request to upstream
    upstream.write_all(&req_data).await?;
    upstream.flush().await?;

    // Stream response (replaces read_http_response + client.write_all)
    if let Some((req_id, t0)) = &request_id {
        stream_http_response(&mut upstream, client, req_id, *t0, &host).await
    } else {
        // Non-AI request — simple pipe (still streaming)
        stream_response_simple(&mut upstream, client).await
    }
```

`stream_response_simple()`：不审计，纯 `tokio::io::copy` 边读边转发（300s 超时）。

**测试**：

```rust
#[test]
fn test_stream_http_response_header_parsing() {
    // Build a minimal HTTP response
    let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
    let (status, headers, _) = parse_response_head(resp).unwrap();
    assert_eq!(status, 200);
    assert!(headers.iter().any(|(k, _)| k.to_lowercase() == "content-type"));
}
```

**验证**：
```bash
cargo build --release
cargo test
# 端到端：发送 stream=true 的 AI 请求，观察客户端逐 chunk 收到数据
```

---

### R4.2 NEW-1 — peek_buf 增大到 16384 字节

**根因**：`proxy.rs handle_connection()` 中 `peek_buf = [0u8; 1024]`。带 ALPN + key_share + session_ticket 等扩展的 TLS ClientHello 可能超过 1024 字节。截断后 `extract_sni()` 返回 None → AI host 被错误 blind tunnel。

**改动文件**：`src/proxy.rs`

**改动**：

```rust
// 旧:
let mut peek_buf = [0u8; 1024];

// 新:
let mut peek_buf = [0u8; 16384]; // TLS record max = 16384, 足够容纳完整 ClientHello
```

仅改一行，但至关重要。

**验证**：
```bash
cargo build --release
cargo test
# 验证 extract_sni 对大 ClientHello 仍正确提取 SNI
```

---

### R4 验证

```bash
# 1. 编译
export PATH="$HOME/.cargo/bin:$PATH"
export no_proxy="*" NO_PROXY="*"
cargo build --release
cargo test

# 2. 端到端流式测试
./start.sh start
./agw-admit.sh --app "TestApp" curl -sS \
  --cacert certs/ca-cert.pem \
  -X POST https://ai.uniontech.com/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer test-key' \
  -d '{"model":"glm-5","messages":[{"role":"user","content":"hi"}],"stream":true}'
# 预期：逐 chunk 收到 SSE 数据，非长时间阻塞后一次性返回

# 3. 检查审计记录
sqlite3 audit/audit.db \
  "SELECT event, response_status, latency_ms, summary FROM events ORDER BY id DESC LIMIT 5;"
```

---

## 阶段 R5：P1 重要修复

### R5.1 NEW-5 — 恢复 keep-alive 循环

**根因**：C12 修复时删除了 `process_http()` 中的 `loop`，处理一个请求后直接返回，TLS 连接被关闭。OpenAI SDK 等默认 keep-alive，每个请求多一次 TLS 握手。

**修复方案**：恢复循环，但严格按 **请求→响应→请求→响应** 顺序处理（不并发）。这才是禁用 pipelining 的正确做法——pipelining 是客户端在前一个响应到达前发送下一个请求，而 keep-alive 是等响应到达后再发下一个请求。

**改动文件**：`src/http_mitm.rs`

**`process_http()` 改动**：

```rust
pub async fn process_http(
    client: &mut TlsStream<TcpStream>,
    mut upstream: tokio_rustls::client::TlsStream<TcpStream>,
    orig_dst: SocketAddr,
    peer_addr: SocketAddr,
    sni: Option<&str>,
) -> Result<(), BoxError> {
    let host = sni.map(|s| s.to_string()).unwrap_or_else(|| orig_dst.ip().to_string());
    let port = orig_dst.port();

    // Loop for keep-alive: process one request at a time (no pipelining)
    loop {
        let req_data = match tokio::time::timeout(
            Duration::from_secs(30),
            read_http_request(client),
        ).await {
            Ok(Ok(Some(data))) => data,
            Ok(Ok(None)) => return Ok(()), // client closed
            Ok(Err(e)) => return Err(Box::new(e)),
            Err(_) => return Ok(()), // read timeout — close connection gracefully
        };

        // ... parse request, detect AI, audit, forward, stream response ...
        // (same as before, but at the end: continue loop instead of return)

        // Forward request to upstream
        upstream.write_all(&req_data).await?;
        upstream.flush().await?;

        // Stream response
        if let Some((req_id, t0)) = &request_id {
            stream_http_response(&mut upstream, client, req_id, *t0, &host).await?;
        } else {
            stream_response_simple(&mut upstream, client).await?;
        }

        // Loop continues — wait for next request on same connection (keep-alive)
    }
}
```

**验证**：
```bash
cargo build --release
cargo test
# 端到端：连续发送 2 个请求到同一 host，观察第 2 个不需要重新 TLS 握手
```

---

### R5.2 NEW-9 — audit host 优先用 Host header

**根因**：`process_http()` 中 `host = sni.map(|s| s.to_string()).unwrap_or_else(|| orig_dst.ip().to_string())`，审计记录的 host 来自 SNI，但 HTTP Host header 可能含端口号或不同。

**改动文件**：`src/http_mitm.rs`

**改动**：在 `parse_request_head` 之后，从 headers 中提取 Host：

```rust
    // 旧:
    let host = sni.map(|s| s.to_string()).unwrap_or_else(|| orig_dst.ip().to_string());

    // 新: 优先用 Host header，fallback 到 SNI，再 fallback 到 IP
    let host = headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.split(':').next().unwrap_or(v).to_string()) // 去端口号
        .or_else(|| sni.map(|s| s.to_string()))
        .unwrap_or_else(|| orig_dst.ip().to_string());
```

**验证**：
```bash
cargo test
# 检查审计记录中 host 字段来自 Host header
```

---

### R5 验证

```bash
cargo build --release
cargo test
# 端到端：keep-alive 连续请求 + 审计 host 字段验证
```

---

## 阶段 R6：P2 一般修复

### R6.1 NEW-3 — audit channel 改 bounded

**改动文件**：`src/audit.rs`

```rust
// 旧:
let (tx, rx): (Sender<AuditEvent>, Receiver<AuditEvent>) = mpsc::channel();

// 新:
let (tx, rx): (Sender<AuditEvent>, Receiver<AuditEvent>) = mpsc::sync_channel(1000);
```

`audit_log()` 中 `send` 改为 `try_send` 语义（`sync_channel` 的 `send` 是阻塞的，需要改为非阻塞）：

```rust
pub fn audit_log(event: &AuditEvent) {
    let tx_guard = TX.lock().unwrap();
    if let Some(sender) = tx_guard.as_ref() {
        // try_send: non-blocking, drop event if channel full
        match sender.send(event.clone()) {
            Ok(()) => {}
            Err(_) => {
                // Channel full — count dropped events
                static DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let n = DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if n % 100 == 0 {
                    eprintln!("[AUDIT] WARNING: {} events dropped (channel full)", n + 1);
                }
            }
        }
    }
}
```

> 注意：`std::sync::mpsc::SyncSender::send()` 是阻塞的。`sync_channel(N).0` 返回 `SyncSender`。
> 要实现非阻塞 try_send，用 `try_send(event,)` 替代 `send(event)`：

```rust
        match sender.try_send(event.clone()) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => { /* drop + count */ }
            Err(mpsc::TrySendError::Disconnected(_)) => {}
        }
```

---

### R6.2 NEW-4 — blind_tunnel 加 idle 超时

**改动文件**：`src/proxy.rs`

```rust
/// Blind TCP tunnel with 5-minute idle timeout.
async fn blind_tunnel(
    mut client: TcpStream,
    mut upstream: TcpStream,
) -> Result<(), BoxError> {
    let (mut cr, mut cw) = client.split();
    let (mut ur, mut uw) = upstream.split();

    let client_to_upstream = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = tokio::time::timeout(
                Duration::from_secs(300), // 5 min idle
                cr.read(&mut buf),
            ).await
                .map_err(|_| -> BoxError { "blind tunnel idle timeout".into() })??;
            if n == 0 { return Ok(()); }
            uw.write_all(&buf[..n]).await?;
            uw.flush().await?;
        }
    };

    let upstream_to_client = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = tokio::time::timeout(
                Duration::from_secs(300),
                ur.read(&mut buf),
            ).await
                .map_err(|_| -> BoxError { "blind tunnel idle timeout".into() })??;
            if n == 0 { return Ok(()); }
            cw.write_all(&buf[..n]).await?;
            cw.flush().await?;
        }
    };

    tokio::try_join!(client_to_upstream, upstream_to_client)?;
    Ok(())
}
```

需要加 `use tokio::io::{AsyncReadExt, AsyncWriteExt};` 回到 proxy.rs。

---

### R6.3 NEW-6 — --ssl-insecure 参数实现

**改动文件**：`src/http_mitm.rs`、`src/tls.rs`

方案：实现 `insecure` 参数。当 `false` 时用 rustls 默认 root certs 验证上游证书。

```rust
// tls.rs 新增:
pub fn client_config_secure() -> Arc<rustls::ClientConfig> {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
    };
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    )
}
```

> 需要新增依赖 `webpki-roots = "=0.26.0"`（edition2021 兼容）。

```rust
// http_mitm.rs:
impl UpstreamConnector {
    pub fn new(insecure: bool) -> Arc<Self> {
        let tls_config = if insecure {
            crate::tls::Certifier::client_config_insecure()
        } else {
            crate::tls::Certifier::client_config_secure()
        };
        Arc::new(Self { tls_config })
    }
}
```

---

### R6.4 NEW-7 — flush() 等待 writer thread 退出

**改动文件**：`src/audit.rs`

```rust
use std::sync::Mutex;
use std::thread::JoinHandle;

static TX: LazyLock<Mutex<Option<Sender<AuditEvent>>>> = LazyLock::new(|| Mutex::new(None));
static WRITER_HANDLE: LazyLock<Mutex<Option<JoinHandle<()>>>> = LazyLock::new(|| Mutex::new(None));

pub fn audit_init(db_path: &Path, jsonl_path: &Path) -> Result<(), String> {
    // ... existing code ...

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

pub fn flush() {
    // Drop sender to close channel
    let mut tx_guard = TX.lock().unwrap();
    *tx_guard = None;
    drop(tx_guard;

    // Wait for writer thread to finish (with 5s timeout)
    let mut h_guard = WRITER_HANDLE.lock().unwrap();
    if let Some(handle) = h_guard.take() {
        // JoinHandle::join is blocking — run in a blocking thread to avoid
        // blocking the async runtime, with a timeout
        let start = std::time::Instant::now();
        while !handle.is_finished() && start.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if !handle.is_finished() {
            eprintln!("[AUDIT] WARNING: writer thread did not finish in 5s");
        }
    }
}
```

> 使用 `JoinHandle::is_finished()` 轮询 + 5s timeout，替代固定 `sleep(500ms)`。

---

### R6.5 NEW-8 — do_foreground() 改用 wait_for_port

**改动文件**：`start.sh`

```bash
# 旧 (do_foreground):
sleep 1.5

# 新:
wait_for_port "$PROXY_PORT" 50 || echo "[start.sh] WARNING: proxy port not ready yet"
```

---

### R6.6 NEW-10 — ca.rs 缓存 CA Certificate 对象

**改动文件**：`src/ca.rs`

```rust
pub struct CaCert {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    ca_key: KeyPair,
    // 缓存 CA params + CA cert 对象，避免每次 generate_leaf 重新解析+自签
    ca_params: CertificateParams,
}

impl CaCert {
    fn load_pem(...) -> Result<Self, String> {
        // ... parse cert_der, key_der, ca_key ...
        let ca_params = CertificateParams::from_ca_cert_der(&cert_der)
            .map_err(|e| format!("ca params from der: {e}"))?;
        Ok(Self { cert_der, key_der, ca_key, ca_params })
    }

    fn generate_and_save(...) -> Result<Self, String> {
        // ... generate params, key, cert ...
        let ca_params = params; // 保存 params（不是 move 给 self_signed）
        // 重新自签获取 cert_der
        let cert = ca_params.self_signed(&ca_key)?;
        let cert_der = cert.der().clone();
        Ok(Self { cert_der, key_der, ca_key, ca_params })
    }

    pub fn generate_leaf(&self, hostname: &str) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), String> {
        // 直接用缓存的 ca_params，不再每次 from_ca_cert_der
        let ca_cert = self.ca_params.self_signed(&self.ca_key)
            .map_err(|e| format!("ca self_signed: {e}"))?;

        let mut params = CertificateParams::new(vec![hostname.to_string()])
            .map_err(|e| format!("leaf params: {e}"))?;
        // ... not_before, not_after ...

        let key_pair = KeyPair::generate()?;
        let cert = params.signed_by(&key_pair, &ca_cert, &self.ca_key)?;
        Ok((cert.der().clone(), key_pair.serialize_der().try_into()?))
    }
}
```

> 仍然每次 `ca_params.self_signed(&ca_key)` 生成 CA cert 对象，因为 rcgen 的 `signed_by` 需要 `&Certificate`。
> 但省去了 `from_ca_cert_der()` 的 DER→params 解析（~0.5ms）。
> 完全消除自签开销需要缓存 `Certificate` 对象，但 rcgen 的 `Certificate` 不是 `Clone`，只能用 `RwLock<Option<Certificate>>` 重新生成。
> 实际收益有限（cert cache 命中后不再调 generate_leaf），此项优先级最低。

---

### R6 验证

```bash
# 1. 编译无 warning
export PATH="$HOME/.cargo/bin:$PATH"
export no_proxy="*" NO_PROXY="*"
cargo build --release 2>&1 | grep -c warning  # 预期: 0 或仅 key_der dead_code
cargo test

# 2. 验证 bounded channel
# (高并发测试：同时发送 50 个请求，检查无 dropped events)

# 3. 验证 blind tunnel 超时
# (发起非 AI HTTPS 请求，5 分钟后检查 tokio task 是否释放)

# 4. 验证 --ssl-insecure=false
./target/release/agentgateway --ssl-insecure=false --port 8444 &
# 发送请求到真实 AI API，观察上游 TLS 验证是否生效

# 5. 验证 flush
kill -TERM <proxy_pid>
# 检查日志中 [SHUTDOWN] Done. 前是否有 [AUDIT] writer thread finished
```

---

## 风险评估

| 修复项 | 风险 | 缓解 |
|--------|------|------|
| R4.1 SSE streaming | 改动大，可能引入响应截断 bug | 保留 Content-Length 读取逻辑，只对 chunked/close 改为流式 |
| R4.2 peek_buf 16384 | 内存：每连接 16KB peek buffer | 1024→16384，16x，但只在 peek 阶段短暂存在 |
| R5.1 keep-alive 循环 | 循环中某个请求失败会关闭整个连接 | 每个请求独立 try/catch，失败则关闭连接 |
| R6.3 --ssl-insecure | 新增 webpki-roots 依赖 | pin `=0.26.0`，edition2021 兼容 |
| R6.4 flush() | JoinHandle::is_finished() 轮询 | 5s timeout + warning log |

---

## 修复后 commit 计划

```
commit 1: fix(NEW-2,NEW-1): SSE 流式响应边读边转发 + peek_buf 增大到 16384
commit 2: fix(NEW-5,NEW-9): 恢复 keep-alive 循环 + audit host 用 Host header
commit 3: fix(NEW-3..NEW-10): bounded channel + blind_tunnel 超时 + ssl-insecure + flush + start.sh + ca.rs
```
