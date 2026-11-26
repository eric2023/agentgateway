# 方案 C 缺陷审查

> 审查时间：2026-11-26
> 审查范围：`src/*.rs`（1705 行）、`start.sh`、`setup_iptables.sh`、`dashboard/dashboard.py`、`Cargo.toml`
> 审查方法：逐文件代码审查 + 架构分析

---

## 严重缺陷（P0：影响核心功能）

### C01. TLS MITM 使用 IP 而非 SNI 作为 hostname

**文件**：`src/proxy.rs:103`、`src/tls.rs`

```rust
// proxy.rs handle_tls_mitm()
let hostname = orig_dst.ip().to_string();
let server_config = certifier.server_config(&hostname)?;
```

**问题**：`orig_dst.ip()` 是 REDIRECT 后的原始目标 IP（如 `1.2.3.4`），不是域名。rustls 客户端侧 `connect_tls()` 也用 `addr.ip().to_string()` 作 `ServerName`。后果：

1. **客户端 TLS 验证失败**：Agent 看到的证书 CN/SAN 是 IP 字符串（如 `1.2.3.4`），但 Agent 请求的 Host 是域名（如 `api.openai.com`）。即使 Agent 信任 CA，证书 SAN 不匹配域名 → TLS 握手失败。
2. **上游 TLS SNI 缺失**：用 IP 作 `ServerName` 连接上游，上游服务器收不到 SNI，可能返回错误证书或拒绝连接（虚拟主机场景）。
3. **证书缓存低效**：每个不同 IP 生成一张证书，但同一域名可能有多个 IP → 缓存膨胀且重复生成。

**正确做法**：
- 客户端侧：从 TLS ClientHello 中提取 SNI（rustls `Acceptor` 的 `ClientHello` 提供 SNI），用 SNI hostname 生成叶子证书。
- 上游侧：用 SNI hostname 作 `ServerName` 连接上游，而非 IP。
- orig_dst 仅用于 TCP 连接地址，不用于 TLS 身份。

### C02. HTTP 请求转发是"读完整请求再转发"，不支持流式 body

**文件**：`src/http_mitm.rs:read_http_request()`

```rust
// 读取直到 \r\n\r\n，再按 Content-Length 读完整 body
while buf.len() < header_end + cl {
    let n = reader.read(&mut tmp).await?;
    ...
}
```

**问题**：对于大请求体（如上传文件、大 prompt），代理必须缓存整个请求体后才转发，增加延迟和内存。更严重的是：

1. **chunked 请求体未处理**：`read_http_request()` 注释说"chunked transfer encoding not fully handled here"——对 chunked 请求只读到 header 结束就返回，body 被截断。
2. **SSE 流式响应的 chunked 检测有 bug**：`read_http_response()` 检测 `b"0\r\n\r\n"` 作为 chunked 结束标记，但实际 chunked 编码中 `"0"` 可能出现在 chunk 数据中（如 JSON 中包含 `0` 字符后跟 `\r\n\r\n`），导致提前截断。

### C03. 非 AI 请求也经过 TLS MITM，但不审计也不必要

**文件**：`src/proxy.rs:handle_connection()`

```rust
if n > 0 && peek_buf[0] == 0x16 {
    // TLS — MITM
    handle_tls_mitm(client, orig_dst, peer_addr, certifier, connector).await
} else {
    // Non-TLS — blind tunnel
    blind_tunnel(client, upstream).await
}
```

**问题**：所有 TLS 连接都被 MITM（终止 TLS → 解析 HTTP → 再连上游 TLS），包括非 AI 请求。这带来：

1. **性能开销**：非 AI 请求也要两次 TLS 握手（客户端→代理 + 代理→上游），延迟翻倍。
2. **兼容性风险**：某些 TLS 客户端（如 Java truststore、cert pinning 应用）会拒绝 MITM 证书。
3. **不必要的安全暴露**：代理能看到所有 HTTPS 明文，而非仅 AI 请求。

**方案 C 原设计**：spec 中说"非 AI 请求 → 直接转发（仍经 MITM TLS，但无审计）"，但这是性能与安全的 trade-off。**应改为**：先 peek ClientHello SNI，仅对 `should_mitm_host()` 匹配的 host 做 MITM，其余 blind tunnel。

### C04. SQLite 全局 Mutex 阻塞 async 运行时

**文件**：`src/audit.rs`

```rust
static DB: Mutex<Option<Connection>> = Mutex::new(None);

pub fn audit_log(event: &AuditEvent) {
    let mut db_guard = DB.lock().unwrap();  // 阻塞锁
    if let Some(conn) = db_guard.as_ref() {
        let _ = conn.execute(...);
    }
}
```

**问题**：`audit_log()` 在 tokio async 任务中同步调用，`std::sync::Mutex` 在 `conn.execute()` 期间持有锁。SQLite 写入（即使是 WAL）在磁盘 I/O 时会阻塞 tokio worker 线程。高并发时（多个 AI 请求同时审计），所有请求排队等待写锁。

**影响**：不是崩溃级 bug，但在高负载下会降低吞吐量。每次写入约 1-5ms，100 并发 = 100-500ms 排队。

**缓解**：用 `tokio::task::spawn_blocking` 包装 SQLite 写入，或用 channel 将审计事件发送到专用写入线程。

### C05. 旧 Python 代理代码未删除

**文件**：`gateway/agentgatewayd.py`（70KB）、`gateway/agw_addon.py`（11KB）、`gateway/gen_ca.py`（3KB）

**问题**：方案 C 实施计划 3.2 要求删除旧 Python 代理代码，但文件仍在。这造成：

1. **混淆**：维护者不知道哪个是当前实现。
2. `setup_iptables.sh` 仍引用 mitmproxy CA 生成逻辑（`timeout 3 mitmdump`），但 mitmproxy 已不再安装。
3. `gateway/__pycache__/` 仍存在。

### C06. setup_iptables.sh 仍使用 mitmproxy CA

**文件**：`setup_iptables.sh:97-110`

```bash
MITM_CA_DIR="$HOME/.mitmproxy"
MITM_CA_SRC="$MITM_CA_DIR/mitmproxy-ca-cert.pem"
# Generate mitmproxy CA on first run
if [[ ! -f "$MITM_CA_SRC" ]]; then
    timeout 3 mitmdump --quiet 2>/dev/null || true
fi
```

**问题**：setup 脚本仍尝试用 `mitmdump` 生成 CA，但 mitmproxy 已被 Rust 替代。实际 CA 在 `certs/ca-cert.pem`，但脚本不安装它。新部署时系统 CA 不会被安装 → Agent 不信任代理证书 → TLS 失败。

---

## 重要缺陷（P1：影响可靠性）

### C07. 证书缓存无上限，内存泄漏

**文件**：`src/tls.rs`

```rust
cache: RwLock<HashMap<String, Arc<TlsCert>>>,
```

**问题**：`HashMap` 无 LRU 淘汰，每个新 hostname 添加一个条目，永不清理。spec 设计说"LRU 1000"，但实现是无限增长。长期运行后，如果 Agent 连接大量不同域名，内存持续增长。

### C08. read_http_response 对无 Content-Length 响应读直到 EOF

**文件**：`src/http_mitm.rs:read_http_response()`

```rust
} else {
    // No Content-Length, no chunked — read until EOF
    loop {
        let n = reader.read(&mut tmp).await?;
        if n == 0 { break; }
        buf.extend_from_slice(&tmp[..n]);
    }
}
```

**问题**：HTTP/1.1 默认 keep-alive，服务器不关连接。无 Content-Length 且非 chunked 时，代理会一直阻塞等待 EOF，永远不返回响应给客户端。Agent 超时后断开，但代理任务泄漏。

**触发场景**：某些 API 返回 204 No Content 或使用 connection close 但代理未检测。

### C09. attribution 缓存以 peer_port 为 key，30s 内可能错误

**文件**：`src/attribution.rs`

```rust
static CACHE: LazyLock<Mutex<HashMap<u16, CacheEntry>>> = ...;
```

**问题**：`peer_port` 是客户端临时端口，连接关闭后操作系统可能复用该端口给其他进程。30s TTL 内如果端口被复用，缓存返回错误的 agent 归因。

**影响**：审计日志中 agent_id/app_name 可能张冠李戴。概率低（30s 内端口复用 + 不同 Agent 恰好用同一端口），但不可忽视。

### C10. uuid_v4 不是 UUID

**文件**：`src/http_mitm.rs:389-397`

```rust
fn uuid_v4() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("{:016x}{:016x}", now, std::process::id() as u128)
}
```

**问题**：不是 UUID v4（无随机性、无版本位）。同一纳秒内同进程的两次调用生成相同 ID。高并发时 request_id 碰撞 → 审计日志中请求和响应配对错误。

### C11. 无连接超时和错误恢复

**文件**：`src/proxy.rs`、`src/http_mitm.rs`

**问题**：
- 上游 TCP 连接无超时：如果上游不可达，`connector.connect_tcp()` 会阻塞直到 OS 默认超时（通常 75s+），期间代理任务和客户端连接都挂起。
- TLS 握手无超时。
- HTTP 读取无超时：`read_http_request()` / `read_http_response()` 无超时，慢速客户端/上游会永久占用 tokio 任务。

### C12. keep-alive 连接中多个 HTTP 请求的处理有竞态

**文件**：`src/http_mitm.rs:process_http()`

```rust
loop {
    let req_data = read_http_request(client).await?;
    // ... process ...
    upstream.write_all(&req_data).await?;
    let resp_data = read_http_response(&mut upstream).await?;
    client.write_all(&resp_data).await?;
}
```

**问题**：如果客户端发送 pipelined 请求（HTTP/1.1 pipelining），`read_http_request` 可能读到下一个请求的开头，但 `read_http_response` 只读一个响应。请求和响应错位。

---

## 一般缺陷（P2：影响可维护性）

### C13. Cargo.toml 中 hyper/hyper-util/http-body-util 实际未使用

**文件**：`Cargo.toml`

```toml
hyper = { version = "=1.5.1", features = ["full"] }
hyper-util = { version = "=0.1.10", features = ["full"] }
http-body-util = "=0.1.2"
```

**问题**：`http_mitm.rs` 注释说"Uses hyper for HTTP/1.1 parsing"，但实际是手动字节解析 HTTP，没有 `use hyper::` 任何东西。这三个依赖是无用的编译开销和攻击面。

### C14. `should_mitm_host()` 函数定义但从未调用

**文件**：`src/detect.rs:165`

```rust
pub fn should_mitm_host(host: &str) -> bool { ... }
```

**问题**：`should_mitm_host()` 检查 host 是否在 AI_HOST_PATTERNS 中，但 `proxy.rs` 中所有 TLS 连接都被 MITM，没有调用此函数过滤。这是 C03 的根因——函数存在但未接线。

### C15. `AI_HOST_PATTERNS` 常量定义但未使用

**文件**：`src/detect.rs:28`

编译器已警告 `AI_HOST_PATTERNS` never used。与 C14 相关。

### C16. `UpstreamConnector::insecure` 字段未使用

**文件**：`src/http_mitm.rs:23`

```rust
pub struct UpstreamConnector {
    insecure: bool,  // warning: field `insecure` is never read
    tls_config: Arc<rustls::ClientConfig>,
}
```

`insecure` 存储了但从未读取——`client_config_insecure()` 总是生成 insecure 配置，忽略 `insecure` 参数。

### C17. `client_read_buf` 死代码

**文件**：`src/http_mitm.rs:55`

```rust
let mut client_read_buf: Vec<u8> = Vec::new();
let _ = client_read_buf;
```

### C18. truncate_json 可能在 UTF-8 字符中间截断

**文件**：`src/audit.rs:truncate_json()`

```rust
fn truncate_json(v: &Value) -> String {
    let s = serde_json::to_string(v).unwrap_or_default();
    if s.len() > MAX_BODY_SIZE {
        s[..MAX_BODY_SIZE].to_string()  // 可能截断在 UTF-8 多字节中间
    } else { s }
}
```

**问题**：`s[..MAX_BODY_SIZE]` 按 byte 截断，如果 64KB 边界恰好在多字节 UTF-8 字符中间，生成的 JSON 字符串无效，存入 SQLite 后读取时会乱码或解析失败。

### C19. 无 graceful shutdown

**文件**：`src/main.rs`

`start.sh stop` 发送 SIGTERM，但 `main.rs` 无 signal handler，tokio 进程直接退出。正在处理的连接被中断，审计日志可能丢失最后一条。

### C20. start.sh 中 `sleep 0.5` 可能不够

**文件**：`start.sh:110`

Rust 代理启动需要加载 CA + 初始化 SQLite（~100ms），0.5s 通常够，但在磁盘慢的机器上可能不够。Dashboard 启动时 SQLite 还没准备好 → 查询失败。

---

## 缺陷汇总

| 编号 | 严重性 | 组件 | 摘要 |
|------|--------|------|------|
| C01 | P0 | tls/proxy | TLS MITM 用 IP 而非 SNI → 证书不匹配 → TLS 失败 |
| C02 | P0 | http_mitm | chunked 请求体未处理，chunked 响应检测有 bug |
| C03 | P0 | proxy | 非 AI 请求也被 MITM → 性能+兼容性 |
| C04 | P1 | audit | SQLite 全局 Mutex 阻塞 async |
| C05 | P1 | gateway | 旧 Python 代码未删除 |
| C06 | P1 | setup | setup_iptables.sh 仍用 mitmproxy CA |
| C07 | P1 | tls | 证书缓存无上限 |
| C08 | P1 | http_mitm | 无 Content-Length 响应读直到 EOF → 阻塞 |
| C09 | P1 | attribution | 端口复用导致缓存错误归因 |
| C10 | P1 | http_mitm | uuid_v4 无随机性 → request_id 碰撞 |
| C11 | P1 | proxy | 无连接/读取超时 |
| C12 | P1 | http_mitm | HTTP pipelining 竞态 |
| C13 | P2 | Cargo.toml | hyper 等三个依赖未使用 |
| C14 | P2 | detect | should_mitm_host 未接线 |
| C15 | P2 | detect | AI_HOST_PATTERNS 未使用 |
| C16 | P2 | http_mitm | insecure 字段未使用 |
| C17 | P2 | http_mitm | client_read_buf 死代码 |
| C18 | P2 | audit | truncate_json UTF-8 截断 |
| C19 | P2 | main | 无 graceful shutdown |
| C20 | P2 | start.sh | sleep 0.5 可能不够 |

---

## 修复优先级建议

### 立即修复（阻断端到端可用）

1. **C01**：从 ClientHello 提取 SNI，用 SNI 生成证书 + 连接上游
2. **C06**：setup_iptables.sh 改用 `certs/ca-cert.pem`
3. **C05**：删除旧 Python 代理代码

### 短期修复（影响可靠性）

4. **C03 + C14**：接线 `should_mitm_host()`，非 AI host blind tunnel
5. **C08**：无 Content-Length 响应改为 read-until-close + 超时
6. **C02**：正确处理 chunked 请求体
7. **C10**：用 `rand` 或 `/dev/urandom` 生成真随机 UUID
8. **C11**：添加 TCP/TLS/HTTP 超时

### 中期优化

9. **C04**：SQLite 写入移到 spawn_blocking 或专用线程
10. **C07**：证书缓存加 LRU 上限
11. **C13**：移除未使用的 hyper 依赖
12. **C18**：UTF-8 安全截断
13. **C19**：添加 SIGTERM graceful shutdown
