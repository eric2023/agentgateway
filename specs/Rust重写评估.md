# 方案 A：Python(mitmproxy) → Rust 重写评估

> 2026-11-26
> 触发原因：Python 实现内存泄漏导致系统卡死（dashboard 22GB + mitmdump 30GB = 52.9GB，耗尽 23GB RAM + 31GB Swap）

---

## 一、泄漏根因分析

### 1.1 dashboard.py 泄漏（RSS 11.6GB + Swap 10.8GB = 22.4GB）

**根因**：`read_audit_events()` 每次将整个 `audit.jsonl`（已膨胀到 1.1GB）读入内存。

```python
# 每次 API 请求都执行：
with open(AUDIT_LOG, "r") as f:
    for line in f:
        events.append(json.loads(line))  # 1.1GB → 全部加载到内存
```

然后 `get_stats()` / `get_ai_requests()` / `get_traces()` 各自对 `events` 做列表推导（`blocked + forwarded + audited` 创建 3 份副本），峰值内存 = 1.1GB × 4 ≈ 4.4GB/次。dashboard 前端每 5s 轮询一次，14 小时内 10080 次轮询，Python GC 不及时回收 → 碎片化膨胀到 22GB。

**直接原因**：audit.jsonl 无限增长到 1.1GB（11601 行，平均 98KB/行，因为 request_body 存了完整对话历史）。

### 1.2 mitmdump 线程泄漏（951 线程 + 30.5GB）

**根因**：mitmproxy 5.3.0 transparent 模式使用同步线程模型（每连接一线程）。SSE 流式 AI 请求是长连接（持续数十秒到数分钟），线程不释放。14 小时内累积 951 个未释放的流式连接线程。

mitmproxy 5.3.0 不支持 async（mitmproxy 8+ 才全面 async），线程数随长连接数线性增长。这是架构性限制，无法通过 addon 代码修复。

### 1.3 结论

| 泄漏源 | 根因 | 能否在 Python 框架内修复 |
|--------|------|--------------------------|
| dashboard.py 22GB | 全量读取 1.1GB 日志 + 列表副本 | ✅ 可修复（限制读取行数 + 流式处理） |
| mitmdump 30GB | mitmproxy 5.3.0 同步线程 + SSE 长连接 | ❌ 架构限制，需升级 mitmproxy 8+ 或换框架 |
| audit.jsonl 1.1GB | request_body 存完整对话历史 | ✅ 可修复（截断 body + 日志轮转） |

---

## 二、Rust 重写可行性评估

### 2.1 Rust 生态现状

| 能力 | Python(mitmproxy 5.3.0) | Rust 生态 | 评估 |
|------|--------------------------|-----------|------|
| 透明拦截 | `--mode transparent`（SO_ORIGINAL_DST） | `tinspect` crate（TPROXY）/ 手动 `SO_ORIGINAL_DST` | ✅ 可行 |
| TLS MITM | 内置（OpenSSL） | `rustls` + `rcgen`（动态证书生成） | ✅ 可行，且更安全（内存安全） |
| HTTP/1.1 | 内置 | `hyper` 1.x | ✅ 成熟 |
| HTTP/2 | mitmproxy 5.3.0 不支持 | `h2` crate / `hyper` | ✅ Rust 反而更好 |
| WebSocket | 内置 | `tokio-tungstenite` | ✅ 可行 |
| SSE 流式 | 支持（但线程泄漏） | `hyper` Stream body（async，无线程泄漏） | ✅ **核心优势** |
| 进程归因 | `/proc/net/tcp` + `/proc/*/fd` 扫描 | 同（syscall 级别相同） | ✅ 可行 |
| CA 管理 | mitmproxy 自管 | `rcgen` 生成 CA + 叶子证书 | ✅ 可行，需自行实现 |
| 审计日志 | Python JSON | `serde_json` + `AppendBufWriter` | ✅ 更高效 |

### 2.2 可用 Rust 库

| 库 | 版本 | 用途 | 成熟度 |
|----|------|------|--------|
| `hyper` | 1.x | HTTP/1.1 + HTTP/2 解析 | ⭐⭐⭐⭐⭐ 生产级 |
| `rustls` | 0.23 | TLS 终止（服务端 + 客户端） | ⭐⭐⭐⭐⭐ 生产级 |
| `rcgen` | 0.13 | CA + 动态证书生成 | ⭐⭐⭐⭐ 可用 |
| `tokio` | 1.x | async runtime（线程池，非一线程一连接） | ⭐⭐⭐⭐⭐ 生产级 |
| `tokio-tungstenite` | 0.24 | WebSocket | ⭐⭐⭐⭐ 可用 |
| `serde_json` | 1.x | JSON 解析（比 Python json 快 5-10x） | ⭐⭐⭐⭐⭐ 生产级 |
| `axum` | 0.8 | Dashboard HTTP 服务器 | ⭐⭐⭐⭐⭐ 生产级 |
| `http-mitm-proxy` | 0.18 | MITM 代理库（封装 hyper+rustls） | ⭐⭐⭐ 新但可用 |
| `tinspect` | 0.x | 透明代理 + MITM（TPROXY） | ⭐⭐ 实验，不直接用 |

**关键架构差异**：Rust 用 `tokio` async runtime，所有连接在固定线程池（默认 = CPU 核数）上多路复用。1000 个并发 SSE 长连接 = 16 个线程（而非 1000 个），内存占用稳定在 ~50MB。

### 2.3 重写架构设计

```
agentgateway (Rust 单二进制)
├── src/
│   ├── main.rs          — CLI (start/stop/status/setup)
│   ├── proxy.rs         — 透明代理核心 (SO_ORIGINAL_DST + TLS MITM + HTTP)
│   ├── tls.rs           — CA 加载 + 动态证书生成 (rcgen + rustls)
│   ├── audit.rs         — 审计日志 (serde_json + 轮转)
│   ├── attribution.rs   — 进程归因 (/proc/net/tcp + /proc/*/fd)
│   ├── detect.rs        — AI 请求识别 (路径/Header/Body 信号)
│   └── dashboard.rs     — 内嵌 Web UI (axum + 静态 HTML)
├── Cargo.toml
└── build.rs             — 嵌入 HTML 到二进制
```

**单二进制部署**：不需要 mitmproxy / python3 / dashboard.py 三个进程，一个二进制包含全部功能。

### 2.4 重写工作量估算

| 模块 | 行数估算 | 难度 | 依赖 |
|------|----------|------|------|
| 透明代理 + SO_ORIGINAL_DST | ~200 | 中 | libc syscall |
| TLS MITM (rustls + rcgen) | ~300 | 高 | rustls, rcgen |
| HTTP 解析 + 转发 (hyper) | ~200 | 中 | hyper |
| AI 请求识别 | ~100 | 低 | serde_json |
| 进程归因 | ~150 | 中 | /proc 扫描 |
| 审计日志 + 轮转 | ~100 | 低 | serde_json |
| Dashboard (axum + HTML) | ~300 | 中 | axum, askama |
| CLI + 配置 | ~100 | 低 | clap |
| **合计** | **~1450 行 Rust** | | |

对比当前 Python：297（addon）+ 583（agentgatewayd 清理后）+ 535（dashboard）= **1415 行有效 Python**（不含死代码）。

### 2.5 Rust 方案 vs Python 方案对比

| 维度 | Python(mitmproxy 5.3.0) | Rust(自研) | 胜者 |
|------|--------------------------|------------|------|
| **内存安全** | ❌ 泄漏（GC 不及时 + 全量读取） | ✅ 无 GC，内存可控 | Rust |
| **线程模型** | ❌ 同步线程（mitmproxy 5.3.0）| ✅ tokio async（固定线程池）| Rust |
| **SSE 长连接** | ❌ 每连接占一线程，951 线程 | ✅ async 多路复用，16 线程 | Rust |
| **内存占用** | ❌ 52.9GB（泄漏时）| ✅ 预计 < 50MB | Rust |
| **HTTP/2 支持** | ❌ mitmproxy 5.3.0 不支持 | ✅ hyper 原生支持 | Rust |
| **部署复杂度** | ❌ 需 mitmproxy + python3 + 多进程 | ✅ 单二进制 | Rust |
| **开发速度** | ✅ 已完成 80% | ❌ 需从头写 | Python |
| **TLS 兼容性** | ✅ OpenSSL（广兼容） | ⚠️ rustls（不支持部分旧 cipher） | Python |
| **调试便利性** | ✅ 热重载 addon | ❌ 需重新编译 | Python |
| **生态成熟度** | ✅ mitmproxy 10年+ | ⚠️ http-mitm-proxy 0.18 | Python |
| **进程归因** | 相同（/proc 扫描） | 相同 | 平 |
| **审计日志** | 相同 | 相同（但更快） | Rust |

### 2.6 Rust 方案的风险

| 风险 | 影响 | 缓解 |
|------|------|------|
| TLS 兼容性 | rustls 不支持 RSA key exchange（仅 ECDHE），极少数旧服务器可能失败 | 用 `openssl` crate 替代 rustls（但失去内存安全优势） |
| http-mitm-proxy 不够成熟 | 可能遇到 edge case | 自行基于 hyper + rustls 实现（核心 ~500 行） |
| 开发周期 | 估 3-5 天全职 | 可先用 Rust 重写 proxy + audit，dashboard 保留 Python |
| 4.19 内核 TPROXY | 需要 `ip rule` + `ip route` 配置 | 当前 iptables REDIRECT + SO_ORIGINAL_DST 方案仍可用 |
| HTTP/2 MITM | 需处理 ALPN 协商 | hyper 支持 h2，但 MITM 代理中需显式处理 |

### 2.7 混合方案（推荐过渡路径）

不急于全量 Rust 重写。可分两步：

**第一步（立即，1-2 小时）**：修复 Python 方案的内存泄漏，让系统稳定运行
- dashboard：限制读取最后 N 行 + 流式处理 + 内存上限
- audit.jsonl：request_body 截断 + 日志轮转（已实现 D6）
- mitmdump：添加 `--set connection_strategy=lazy` + 定期重启

**第二步（后续，3-5 天）**：Rust 重写 proxy 核心
- 用 Rust 替代 mitmproxy + agw_addon.py（解决线程泄漏）
- dashboard 可保留 Python（修复后内存可控）或用 axum 重写
- 单二进制部署

---

## 三、决策矩阵

| 方案 | 开发成本 | 内存安全 | HTTP/2 | 部署 | 风险 |
|------|----------|----------|--------|------|------|
| **A. 修复 Python** | 1-2h | ⚠️ 需持续维护 | ❌ | 复杂 | 低 |
| **B. 全量 Rust** | 3-5 天 | ✅ | ✅ | 简单 | 中（TLS 兼容） |
| **C. 混合：Rust proxy + Python dashboard** | 2-3 天 | ✅ proxy | ✅ | 中等 | 低-中 |

---

## 四、建议

**推荐方案 C（混合）**：

1. **立即**：修复 Python dashboard 内存泄漏（1-2h），让系统恢复可用
2. **短期**：用 Rust 重写 proxy 核心（透明代理 + TLS MITM + AI 识别 + 审计），替代 mitmproxy + agw_addon.py
3. **可选**：后续用 axum 重写 dashboard（或保留修复后的 Python dashboard）

理由：
- Python dashboard 泄漏是代码 bug（全量读取），可修复
- mitmproxy 5.3.0 线程泄漏是架构限制，不可修复 → 必须 Rust 替代
- 全量重写 dashboard 投入产出比低（axum 重写 ~300 行，但 Python 修复只需改 ~20 行）
