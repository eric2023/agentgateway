# 方案 A 缺陷审查

> 审查时间：2026-11-25
> 审查范围：spec 文档 + 全部实现代码（agw_addon.py / agentgatewayd.py / setup_iptables.sh / start.sh / agw-admit.sh / dashboard.py）

---

## 一、方案设计缺陷（Spec 层面）

### D1. 不可绕过性被高估

**Spec 声称**（§2）："不可绕过（内核 NAT 重定向）"

**实际**：
- Agent 只需不加入 cgroup 即可绕过（cgroup 纳入是自愿的，不是强制的）
- Agent 可以 fork 子进程后将自己移出 cgroup（`echo $$ > /sys/fs/cgroup/net_cls/../../../tasks`），tasks 文件 chmod 666 意味着进程可以自由移出
- Agent 可以使用非 443/8443/9443 端口绕过（如 :8080、:443 的 IP 直连已被覆盖，但自定义端口未覆盖）
- Spec §6 诚实边界中已承认"无自保护：Agent 可杀网关进程"

**影响**：审计完整性依赖 Agent 配合，不是真正的强制拦截。

### D2. "Agent 零改造" 与 agw-admit 矛盾

**Spec 声称**（§1）："Agent 零改造——不设任何环境变量，不需要修改代码，不需要特殊启动参数"

**实际**：
- 必须通过 `agw-admit.sh` 启动 Agent（或手动写入 cgroup），这本身就是"特殊启动参数"
- `agw-admit.sh` 设置 `AGENTGATEWAY_APP_NAME` / `AGENTGATEWAY_AGENT_ID` / `AGENTGATEWAY_SESSION_ID` 环境变量——与"不设任何环境变量"矛盾
- Spec §3.2 修正为"不再设置 HTTPS_PROXY 等"，但仍设置 AGENTGATEWAY_* 变量

**影响**：Spec 表述误导，应改为"Agent 代码零改造，但需通过 agw-admit 启动"。

### D3. CA 信任链依赖系统 CA 仓库

**Spec 声称**（§3.5）："所有应用自动信任"

**实际**：
- cert pinning 应用（如某些移动端 SDK）不信任系统 CA → Spec §6 已承认
- Java 应用使用独立 truststore（`cacerts`），不读取系统 CA
- Flatpak/Snap 应用有独立 CA 命名空间
- `update-ca-certificates` 只更新 OpenSSL/GnuTLS 信任链，不更新 NSS DB（需单独 `certutil`）

**影响**：部分 Agent 可能因 TLS 验证失败而连接中断。

### D4. 仅拦截 IPv4 :443/:8443/:9443

**Spec**：iptables 规则只覆盖 443、8443、9443 三个端口。

**实际**：
- AI API 可能使用其他端口（如 :8080、:3000）
- IPv6 流量完全不受 iptables-legacy `-m cgroup` 规则约束（cgroup v1 net_cls 不标记 IPv6 socket）
- Agent 可通过 DNS over HTTPS (DoH) 绕过，或通过 HTTP/3 (QUIC/UDP) 绕过（iptables 规则只匹配 TCP）

**影响**：拦截范围有限，依赖端口枚举，无法覆盖所有 AI API 端点。

### D5. 单点故障：mitmproxy 宕机 = Agent 断网

**设计**：iptables REDIRECT 将 cgroup 内进程的 :443 流量重定向到 :8444。

**问题**：mitmproxy 崩溃或重启时，cgroup 内进程的 :443 连接全部被拒绝（connection refused）。Agent 无法正常工作，且错误信息不明确（"connection refused" 而非"代理服务不可用"）。

**Spec 未提及**此故障模式，也无健康检查/自动重启机制。

### D6. 审计日志无上限、无轮转

**设计**：`audit/audit.jsonl` 以 append 模式无限增长。

**实际**：当前已有 4.9MB / 31 条记录。每条 AI 请求包含完整 request_body（可能数万字符），长期运行后日志文件会膨胀到 GB 级。

**影响**：
- 磁盘空间耗尽
- dashboard 每次请求读取全部日志，文件增大后响应变慢
- 无日志清理/轮转机制

### D7. 进程归因依赖 /proc 扫描，性能不可预测

**设计**：`_lookup_peer()` 扫描 `/proc/net/tcp` + `/proc/*/fd/*` 找到连接发起者 PID。

**问题**：
- `/proc/*/fd` 扫描是 O(进程数 × fd数)，系统繁忙时可能扫描数万个 fd
- `_proc_scan_semaphore` 限制并发为 4，但单个扫描仍可能耗时数百毫秒
- 高并发请求时（如 Agent 批量调用），扫描成为瓶颈
- `/proc/net/tcp` 只包含 IPv4 连接，IPv6 连接无法归因

---

## 二、实现缺陷（代码层面）

### I1. start.sh CA 健康检查路径错误 🔴

**文件**：`start.sh:99`
```bash
if [[ ! -f /etc/ssl/certs/agentgateway-ca.pem ]]; then
```

**问题**：实际 CA 安装路径是 `/usr/local/share/ca-certificates/agentgateway-ca.crt`（setup_iptables.sh 第 91 行）。此检查永远为 true，每次启动都打印误导性 WARNING。

**修复**：改为 `/usr/local/share/ca-certificates/agentgateway-ca.crt`

### I2. setup_iptables.sh --help 文本 CA 路径错误 🔴

**文件**：`setup_iptables.sh:42`
```
4. 安装 mitmproxy CA 到 /etc/ssl/certs/agentgateway-ca.pem
```

**问题**：同 I1，帮助文本仍引用旧路径。

**修复**：改为 `/usr/local/share/ca-certificates/agentgateway-ca.crt`

### I3. response() 钩子是空实现，响应数据全部丢失 🔴

**文件**：`agw_addon.py:129-133`
```python
def response(self, flow: http.HTTPFlow):
    """Optionally record response metadata (status, token usage)."""
    pass
```

**问题**：
- `response_status` / `response_body` / `response_headers` / `token_usage` / `latency_ms` 永远不会被写入审计日志
- dashboard `get_ai_requests()` 尝试匹配 `ai_response` 事件，但 addon 从不产生该事件
- dashboard 中 `has_response` 永远为 false，`token_usage` 永远为空
- Spec §3.8 审计日志 Schema 声明包含 `response_status` / `response_body` / `token_usage` / `latency_ms`，但代码不写入
- **跟踪列表中的工具调用结果**（从 response body 提取的 assistant tool_calls）永远为空

**影响**：dashboard 只能显示请求，不能显示响应/token 用量/延迟/工具调用结果。审查能力减半。

### I4. _proc_cache 缓存丢失 agent_id 和 session_id 🟡

**文件**：`agw_addon.py:145-148`（读取）+ `222-225`（写入）

```python
# 写入缓存：4 元素
gw._proc_cache[peer_port] = (agent_pid, agent_comm, app_name, now)

# 读取缓存：返回 5 值，后两个硬编码为 None
return cached[0], cached[1], cached[2], None, None
```

**问题**：缓存命中时，`agent_id` 和 `session_id` 总是 None。`request()` 钩子中 `audit_agent = peer_agent or self.agent_id`，缓存命中时 `peer_agent=None`，导致使用 mitmproxy 自己的随机 agent_id（每次重启变化）。

**影响**：同一 Agent 的不同请求可能被归因到不同的 agent_id（取决于是否命中缓存）。当前请求频率低（30s TTL 内无重复），暂未暴露。

**修复**：缓存结构改为 `(agent_pid, agent_comm, app_name, agent_id, session_id, now)`。

### I5. 手动纳入 cgroup 的进程无 agent_id/session_id 🟡

**场景**：用户手动将进程写入 cgroup tasks（不通过 agw-admit.sh）。

**问题**：
- 没有 `AGENTGATEWAY_AGENT_ID` / `AGENTGATEWAY_SESSION_ID` 环境变量
- `peer_agent = None` → `audit_agent = self.agent_id`（mitmproxy 的随机 ID）
- 每次重启 mitmproxy，agent_id 变化，同一进程的请求被归因到不同 agent

**影响**：手动纳入的进程（如当前 omp）审计日志中 agent_id 是 mitmproxy 的随机值，无实际意义。

**修复建议**：当 env 未设置时，用 exe basename 生成稳定的 agent_id（如 `agent-omp`）。

### I6. _lookup_peer 只读 /proc/net/tcp，不读 /proc/net/tcp6 🟡

**文件**：`agw_addon.py:154`
```python
with open("/proc/net/tcp") as f:
```

**问题**：如果 Agent 连接 IPv6 目标（如 `::1` 或 IPv6 地址），连接信息在 `/proc/net/tcp6` 中，`_lookup_peer` 无法找到，返回全 None。

**影响**：IPv6 连接的请求无进程归因（app_name="transparent"，agent_id 为随机值）。

### I7. agentgatewayd.py 包含 ~1060 行死代码 🟡

**文件**：`agentgatewayd.py:569-1628`

**问题**：以下代码仅被旧 transparent_proxy.py / CONNECT 代理路径使用，mitmproxy addon 不调用：
- `_lookup_peer_process()`（569-723 行）
- `MITMProxyHandler` 类（726-1554 行）
- `ThreadingHTTPProxyServer` 类（1557-1579 行）
- `make_handler_with_session()`（1581-1587 行）
- `main()`（1590-1625 行）
- `load_ca()` / `generate_cert_for_host()`（227-286 行）
- `ToolCallTracker` 类（151-214 行）
- `detect_app_source()`（414-457 行）
- `_get_upstream_socket()` / `_return_upstream_socket()`（294-342 行）

这些代码在模块加载时仍被 Python 解析，`from cryptography import ...` 导致不必要的依赖。

**影响**：维护负担、认知开销、不必要的 cryptography 依赖。

### I8. setup_iptables.sh 直接 sudo 运行时 CA 路径错误 🟡

**文件**：`setup_iptables.sh:89-96`

**场景**：用户直接运行 `sudo bash setup_iptables.sh`（而非 `./start.sh setup`）。

**问题**：
- `sudo` 重置 `$HOME` 为 `/root`
- `MITM_CA_DIR="$HOME/.mitmproxy"` → `/root/.mitmproxy`
- `timeout 3 mitmdump` 以 root 运行，生成 CA 到 `/root/.mitmproxy/`
- 但 mitmproxy 以普通用户运行，读取 `~/.mitmproxy/`（用户 home）
- CA 文件路径不匹配，系统 CA 安装失败

**影响**：直接 sudo 运行 setup 时 CA 安装静默失败（只打印 WARNING）。

**修复**：脚本开头显式设置 `HOME="${SUDO_USER:+$(getent passwd "$SUDO_USER" | cut -d: -f6)}"`
或检测 `$SUDO_USER` 并解析其 home 目录。

### I9. audit_init() 重复调用导致文件句柄泄漏 🟢

**文件**：`agentgatewayd.py:119-124`

```python
def audit_init():
    global _audit_file
    _audit_file = open(path, "a", buffering=1)
```

**问题**：mitmproxy 热重载 addon 时，`__init__` 再次调用 `audit_init()`，旧 `_audit_file` 句柄未关闭。

**影响**：文件句柄泄漏（低频，仅热重载时触发）。

### I10. dashboard 无缓存，每次请求读取全量日志 🟡

**文件**：`dashboard/dashboard.py:43-57`

**问题**：`read_audit_events()` 每次打开 `audit.jsonl` 读取全部行。4.9MB / 31 条记录时尚可，但日志增长后每次 API 调用都重新解析全部 JSON。

**影响**：dashboard 响应时间随日志增长线性恶化。

### I11. setup_iptables.sh --cleanup 不清理 cgroup 🟢

**文件**：`setup_iptables.sh:51-71`

**问题**：`--cleanup` 只删除 iptables 规则，不删除 cgroup 目录、不卸载 xt_cgroup 模块。

**影响**：残留 cgroup 中的进程仍被标记 classid（但无 iptables 规则，不影响网络）。功能上无害，但不是完整的清理。

### I12. agw-admit.sh --app 参数缺值时静默错误 🟢

**文件**：`agw-admit.sh:99-101`
```bash
--app)
    APP_NAME="$2"
    shift 2
    ;;
```

**问题**：如果用户运行 `agw-admit.sh --app`（无参数值），`$2` 为空，`shift 2` 会报错或跳过下一个参数。

**修复**：添加 `[[ -z "${2:-}" ]] && { echo "Error: --app requires a value"; exit 1; }`

### I13. 无 mitmproxy 进程监控/自动重启 🟡

**文件**：`start.sh`

**问题**：`start_proc` 启动 mitmdump 后不监控其存活。如果 mitmdump 崩溃：
1. cgroup 内进程的 :443 连接全部被拒绝（REDIRECT 到无监听的端口）
2. Agent 无法正常工作
3. 无告警、无自动重启

**影响**：mitmproxy 单点故障导致 Agent 断网，且无自动恢复。

### I14. 审计日志 request_body 可能包含完整对话历史 🟡

**文件**：`agw_addon.py:117`
```python
"request_body": request_body,
```

**问题**：`request_body` 存储完整的 JSON dict（不再截断），AI 请求通常包含完整对话历史（system prompt + 所有历史消息）。单个请求可能数十 KB。

**影响**：
- 审计日志膨胀（已有 4.9MB / 31 条 = 平均 158KB/条）
- 敏感信息（对话内容、API key 在 body 中）完整记录
- `request_body_raw`（截断 2000 字符）与 `request_body`（完整）重复存储

---

## 三、严重程度汇总

| ID | 严重度 | 类型 | 描述 |
|----|--------|------|------|
| I1 | 🔴 高 | 实现 | start.sh CA 健康检查路径错误，永远打印 WARNING |
| I2 | 🔴 高 | 实现 | setup_iptables.sh --help CA 路径错误 |
| I3 | 🔴 高 | 实现 | response() 空实现，响应/token/工具调用结果全部丢失 |
| I4 | 🟡 中 | 实现 | 缓存丢失 agent_id/session_id |
| I5 | 🟡 中 | 实现 | 手动纳入 cgroup 的进程无稳定 agent_id |
| I6 | 🟡 中 | 实现 | 不支持 IPv6 连接归因 |
| I7 | 🟡 中 | 实现 | ~1060 行死代码 |
| I8 | 🟡 中 | 实现 | 直接 sudo 运行 setup 时 CA 路径错误 |
| I9 | 🟢 低 | 实现 | audit_init 重复调用文件句柄泄漏 |
| I10 | 🟡 中 | 实现 | dashboard 无缓存，全量读取日志 |
| I11 | 🟢 低 | 实现 | --cleanup 不清理 cgroup |
| I12 | 🟢 低 | 实现 | --app 缺值时静默错误 |
| I13 | 🟡 中 | 实现 | 无进程监控/自动重启 |
| I14 | 🟡 中 | 实现 | request_body 完整存储导致日志膨胀 |
| D1 | 🟡 中 | 设计 | 不可绕过性被高估 |
| D2 | 🟡 中 | 设计 | "零改造"表述与 agw-admit 矛盾 |
| D3 | 🟡 中 | 设计 | CA 信任链覆盖不全 |
| D4 | 🟡 中 | 设计 | 仅拦截 IPv4 三个端口 |
| D5 | 🟡 中 | 设计 | mitmproxy 单点故障导致断网 |
| D6 | 🟡 中 | 设计 | 审计日志无轮转 |
| D7 | 🟡 中 | 设计 | /proc 扫描性能不可预测 |

---

## 四、建议优先修复顺序

1. **I1 + I2**：CA 路径修复（1 分钟，纯文本改动）
2. **I3**：实现 response() 钩子（核心功能缺失）
3. **I4**：修复缓存结构（数据归因正确性）
4. **I5**：手动纳入进程的 agent_id 生成（omp 场景）
5. **I8**：setup_iptables.sh HOME 处理（部署正确性）
6. **I14**：request_body 截断策略（日志膨胀）
7. **I7**：清理死代码（维护性）
