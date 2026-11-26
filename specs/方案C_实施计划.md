# 方案 C 实施计划

> 基于 `specs/方案C_混合方案.md`
> 目标：Rust 替代 mitmproxy 代理核心 + SQLite 替代 JSONL + 修复 Python dashboard
> 预计总工期：3 天

---

## 阶段 0：紧急修复 Python dashboard（让系统立即可用）

> 目标：1-2 小时内让现有 Python 方案恢复可用，不再 OOM
> 在 Rust 重写完成前，系统仍可运行（修复后的 Python 方案）

### 0.1 Python dashboard 改用 SQLite 读取

**文件**：`dashboard/dashboard.py`

**改动**：
- 新增 `get_db()` 函数，连接 `audit/audit.db`（WAL 模式）
- `read_audit_events()` → `get_events(limit, event_type, agent_id)` SQL 查询
- `get_stats()` → `SELECT COUNT(*) GROUP BY decision` / `SELECT host, COUNT(*) GROUP BY host`
- `get_ai_requests()` → `LEFT JOIN events resp ON r.request_id = resp.request_id`
- `get_traces()` → `SELECT ... WHERE agent_id = ? ORDER BY ts_unix`
- 保留 `read_audit_events()` 作为 fallback（如果 SQLite 不存在则读 JSONL）

### 0.2 Python audit_log 改为双写 SQLite + JSONL

**文件**：`gateway/agentgatewayd.py`

**改动**：
- `audit_init()`：打开 SQLite 连接，建表（如果不存在），设置 WAL 模式
- `audit_log()`：INSERT 到 SQLite + 可选写 JSONL（保留人类可读备份）
- 日志清理：每次 `audit_init()` 执行 `DELETE WHERE ts_unix < now - 7 days`

### 0.3 request_body 截断

**文件**：`gateway/agw_addon.py`

**改动**：
- `request_body` 截断到 64KB（存 JSON 字符串前 64KB）
- `response_body` 截断到 64KB
- 移除 `request_body_raw`（已在阶段 3 完成）

### 0.4 验证

```bash
./start.sh restart
# 发送 AI 请求
sqlite3 audit/audit.db "SELECT event, host, model FROM events ORDER BY id DESC LIMIT 5;"
# dashboard 内存检查
ps -o rss= -p $(cat logs/dashboard.pid) | awk '{print $1/1024 " MB"}'
# 应 < 50MB
```

---

## 阶段 1：Rust 代理骨架（透明代理 + TLS MITM）

> 目标：Rust 二进制能接收 iptables REDIRECT 流量，完成 TLS MITM，转发到真实目标
> 预计：1 天

### 1.1 项目初始化

```bash
cargo init --name agentgateway
```

**Cargo.toml**：
```toml
[package]
name = "agentgateway"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["full"] }
hyper = { version = "1", features = ["full"] }
hyper-util = { version = "0.1", features = ["full"] }
http-body-util = "0.1"
bytes = "1"
rustls = "0.23"
tokio-rustls = "0.26"
rcgen = "0.13"
rusqlite = { version = "0.32", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive"] }
libc = "0.2"
```

### 1.2 透明代理核心（`src/proxy.rs`）

**功能**：
- 监听 `127.0.0.1:8444`
- 接受连接 → `getsockopt(SO_ORIGINAL_DST)` 获取原始目标 IP:port
- 判断是否 TLS（端口 443/8443/9443 或 ClientHello 0x16）
- TLS → 调用 `tls.rs` 做 MITM
- 非 TLS → 直接 TCP 转发（透明 pipe）

**关键代码结构**：
```rust
// SO_ORIGINAL_DST
use libc::{getsockopt, SOL_IP, SO_ORIGINAL_DST, sockaddr_in};

async fn handle_connection(stream: TcpStream, state: Arc<AppState>) {
    let orig_dst = get_original_dst(&stream)?;
    if is_tls_port(orig_dst.port()) {
        handle_tls_mitm(stream, orig_dst, state).await;
    } else {
        handle_plain_forward(stream, orig_dst).await;
    }
}
```

### 1.3 TLS MITM（`src/tls.rs`）

**功能**：
- 启动时加载/生成 CA（`~/.agentgateway/ca.pem` + `ca-cert.pem`）
- 从 ClientHello 提取 SNI
- 为 SNI hostname 动态生成叶子证书（rcgen），用 CA 签名
- 缓存叶子证书（`DashMap`，LRU 1000）
- 用 rustls 终止客户端 TLS → 获取明文 HTTP
- 用 rustls 连接真实目标服务器 → 转发

**关键代码结构**：
```rust
struct TlsMitm {
    ca_cert: rcgen::Certificate,  // CA 私钥+证书
    cert_cache: DashMap<String, Arc<rustls::ServerConfig>>,
}

impl TlsMitm {
    async fn handle(&self, client: TcpStream, sni: &str, orig_dst: SocketAddr) {
        let server_config = self.get_or_gen_cert(sni);
        let tls_conn = TlsAcceptor::from(server_config).accept(client).await?;
        // tls_conn 是明文流 → 交给 HTTP 处理
    }
}
```

### 1.4 HTTP 转发（`src/http_mitm.rs`）

**功能**：
- 用 hyper 解析明文 HTTP 请求
- 转发到真实目标（通过 TLS 客户端连接）
- 调用 `detect.rs` 识别 AI 请求
- 调用 `attribution.rs` 做进程归因
- 调用 `audit.rs` 写审计
- 支持 SSE 流式（hyper Stream body，async 不阻塞线程）
- 支持 WebSocket Upgrade

### 1.5 验证

```bash
cargo build --release
# 替换 mitmproxy
./start.sh restart
# Agent 发起 HTTPS 请求 → 应在 audit.db 中看到记录
sqlite3 audit/audit.db "SELECT count(*) FROM events;"
# 内存检查
ps -o rss=,nthreads= -p $(cat logs/proxy.pid)
# 应 < 50MB RSS, < 20 线程
```

---

## 阶段 2：AI 识别 + 进程归因 + 审计（Rust 实现）

> 目标：Rust 代理具备完整的 AI 请求识别、进程归因、SQLite 审计能力
> 预计：0.5 天

### 2.1 AI 请求识别（`src/detect.rs`）

移植 `agentgatewayd.py:detect_ai_request()` 逻辑：
- AI API 路径匹配（`/v1/chat/completions` / `/v1/messages` 等）
- AI Auth Header 匹配（`Authorization: Bearer` / `x-api-key`）
- Body JSON 结构匹配（`messages[]` / `model` / `max_tokens` / `stream`）
- 返回 `(is_ai, confidence, signals, detail)`

### 2.2 进程归因（`src/attribution.rs`）

移植 `agw_addon.py:_lookup_peer()` 逻辑：
- 从客户端 peer_port 扫描 `/proc/net/tcp` + `/proc/net/tcp6` 找 socket inode
- 遍历 `/proc/*/fd/*` 找持有 inode 的 PID
- 读取 `/proc/<pid>/environ` 获取 `AGENTGATEWAY_*` 环境变量
- 父进程链遍历（`/proc/<pid>/stat` → ppid）
- 缓存（`DashMap`，30s TTL）
- agent_id/session_id 回退到 `agent-{app_name}`

### 2.3 SQLite 审计（`src/audit.rs`）

- `audit_init()`：打开 SQLite，建表，设置 WAL
- `audit_log(event)`：`INSERT INTO events (...) VALUES (...)`
- 日志清理：启动时 `DELETE WHERE ts_unix < now - 7 days` + 保留最近 50000 行
- `request_body` / `response_body` 截断到 64KB

### 2.4 验证

```bash
./start.sh restart
# Agent 发起 AI 请求
sqlite3 audit/audit.db "
  SELECT event, app_name, agent_id, host, model, response_status, latency_ms
  FROM events ORDER BY id DESC LIMIT 10;
"
# 进程归因检查
sqlite3 audit/audit.db "SELECT DISTINCT agent_id, app_name FROM events;"
# 应看到 agent-omp / agent-uos-ai 等
```

---

## 阶段 3：Dashboard 改用 SQLite + 清理

> 目标：dashboard 完全改用 SQLite 查询，删除旧 Python 代理代码
> 预计：0.5 天

### 3.1 Dashboard SQLite 查询（`dashboard/dashboard.py`）

**改动**：
- `get_db()` 连接 SQLite
- `get_stats()` → `SELECT decision, COUNT(*) GROUP BY decision`
- `get_ai_requests()` → `LEFT JOIN events resp ON r.request_id = resp.request_id`
- `get_traces()` → `SELECT ... WHERE agent_id != '' ORDER BY ts_unix`
- `extract_tool_calls()` → 逻辑不变（从 JSON body 提取）
- 移除 `read_audit_events()` / `_audit_cache`（不再需要全量读取 + mtime 缓存）

### 3.2 删除旧 Python 代理代码

- 删除 `gateway/agw_addon.py`
- 删除 `gateway/agentgatewayd.py`
- 删除 `gateway/gen_ca.py`
- 删除 `certs/` 目录
- 删除 `audit/audit.jsonl`（如果存在）
- 保留 `dashboard/dashboard.py`（修复后）

### 3.3 start.sh 更新

- `proxy_cmd()` 改为 `./agentgateway`（Rust 二进制）
- 移除 mitmproxy 相关逻辑
- `setup_iptables.sh` CA 生成改为 `./agentgateway --gen-ca`

### 3.4 验证

```bash
./start.sh restart
./start.sh status
# dashboard 内存
ps -o rss= -p $(cat logs/dashboard.pid) | awk '{print $1/1024 " MB"}'
# 应 < 20MB
# Rust 代理内存 + 线程
ps -o rss=,nthreads= -p $(cat logs/proxy.pid)
# 应 < 50MB RSS, < 20 线程
# dashboard 功能验证
curl -s http://127.0.0.1:9090/api/data | python3 -m json.tool | head -20
```

---

## 阶段 4：集成测试 + Spec 更新

> 目标：端到端验证 + 文档更新
> 预计：0.5 天

### 4.1 集成测试

- [ ] Agent 通过 agw-admit 启动 → cgroup 纳入
- [ ] Agent 发起 HTTPS 请求 → iptables REDIRECT → Rust 代理 MITM
- [ ] AI 请求被识别 + 审计 → SQLite 记录
- [ ] 非 AI 请求直接转发（无审计）
- [ ] SSE 流式响应正确转发（不泄漏线程）
- [ ] dashboard 正确展示请求列表 + 响应状态 + token 用量 + 工具调用
- [ ] 长时间运行（1 小时）后内存稳定（< 100MB 总计）
- [ ] 长时间运行后线程数稳定（< 20）

### 4.2 Spec 更新

- `specs/方案C_混合方案.md`：补充实现细节
- `README.md`：更新部署指南（cargo build 替代 pip install mitmproxy）
- `specs/方案A_透明代理进程级拦截_4.19内核.md`：标记为"已废弃，被方案 C 替代"

### 4.3 Git

```bash
git add -A
git commit -m "feat: 方案C——Rust 代理核心 + SQLite 审计 + Python dashboard"
git push origin main
```

---

## 执行顺序与依赖

```
阶段 0（紧急修复 Python）      ← 立即，1-2h
  0.1 dashboard 改 SQLite 读取
  0.2 audit_log 双写 SQLite
  0.3 request_body 截断
  └── 验证：系统恢复可用

阶段 1（Rust 代理骨架）         ← 阶段 0 完成后，1 天
  1.1 cargo init + Cargo.toml
  1.2 透明代理核心 (SO_ORIGINAL_DST)
  1.3 TLS MITM (rustls + rcgen)
  1.4 HTTP 转发 (hyper)
  └── 验证：Rust 能 MITM 转发流量

阶段 2（AI 识别 + 归因 + 审计）  ← 阶段 1 完成后，0.5 天
  2.1 AI 请求识别
  2.2 进程归因
  2.3 SQLite 审计
  └── 验证：SQLite 中有完整审计记录

阶段 3（Dashboard + 清理）      ← 阶段 2 完成后，0.5 天
  3.1 Dashboard SQLite 查询
  3.2 删除旧 Python 代理代码
  3.3 start.sh 更新
  └── 验证：端到端可用，内存稳定

阶段 4（集成测试 + Spec）       ← 阶段 3 完成后，0.5 天
  4.1 集成测试
  4.2 Spec 更新
  4.3 Git push
```

## 里程碑

| 里程碑 | 完成标志 | 预计时间 |
|--------|----------|----------|
| M0：系统恢复可用 | Python dashboard 内存 < 50MB | 阶段 0 完成 |
| M1：Rust 能转发流量 | Rust 二进制替代 mitmproxy，HTTPS 正常 | 阶段 1 完成 |
| M2：完整审计能力 | SQLite 中有 AI 请求 + 响应 + 进程归因 | 阶段 2 完成 |
| M3：全量替换 | 旧 Python 代理代码删除，dashboard 用 SQLite | 阶段 3 完成 |
| M4：交付 | 集成测试通过，Spec 更新，Git push | 阶段 4 完成 |
