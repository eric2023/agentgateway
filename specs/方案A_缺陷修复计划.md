# 方案 A 缺陷修复计划

> 基于 `specs/方案A_缺陷审查.md`，覆盖全部 14 个实现缺陷 + 7 个设计缺陷。
> 按依赖关系分 5 个阶段，每阶段独立可验证、可提交。

---

## 阶段 1：快速修复（路径/文本错误）

> 无依赖，无风险，纯文本改动。

### 1.1 I1 — start.sh CA 健康检查路径错误

**文件**：`start.sh:99`

**改动**：
```diff
-    if [[ ! -f /etc/ssl/certs/agentgateway-ca.pem ]]; then
+    if [[ ! -f /usr/local/share/ca-certificates/agentgateway-ca.crt ]]; then
```

### 1.2 I2 — setup_iptables.sh --help CA 路径错误

**文件**：`setup_iptables.sh:42`

**改动**：
```diff
-  4. 安装 mitmproxy CA 到 /etc/ssl/certs/agentgateway-ca.pem
+  4. 安装 mitmproxy CA 到 /usr/local/share/ca-certificates/agentgateway-ca.crt
```

### 1.3 I8 — setup_iptables.sh 直接 sudo 运行时 HOME 错误

**文件**：`setup_iptables.sh`，在 `set -uo pipefail` 之后（第 15 行后）

**改动**：插入 HOME 修正逻辑：
```bash
# Fix HOME when invoked via sudo without --preserve-env
if [[ -n "${SUDO_USER:-}" && "$HOME" == "/root" ]]; then
    SUDO_HOME="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)"
    [[ -n "$SUDO_HOME" ]] && HOME="$SUDO_HOME"
fi
```

**原理**：`start.sh setup` 用 `sudo --preserve-env=HOME` 已正确；但用户直接 `sudo bash setup_iptables.sh` 时 `$HOME=/root`。此修正检测 `$SUDO_USER` 并还原真实用户 HOME。

### 1.4 I12 — agw-admit.sh --app 缺值时静默错误

**文件**：`agw-admit.sh:99-101`

**改动**：
```diff
         --app)
+            [[ -z "${2:-}" ]] && { echo "[agw-admit] Error: --app requires a value" >&2; exit 1; }
             APP_NAME="$2"
             shift 2
             ;;
```

同样对 `--agent-id` 和 `--session-id` 加相同检查。

**验证**：
```bash
./start.sh status  # 不再打印 CA WARNING
bash setup_iptables.sh -h | grep CA  # 路径正确
./agw-admit.sh --app 2>&1  # 报错退出
```

---

## 阶段 2：核心功能修复（response 钩子 + 进程归因）

> 这是功能性修复，直接解决"跟踪列表无工具信息"和"agent_id 不稳定"问题。

### 2.1 I3 — 实现 response() 钩子，记录响应数据

**文件**：`agw_addon.py:129-133`

**改动**：替换空 `pass` 为完整实现：

```python
def response(self, flow: http.HTTPFlow):
    """Record response metadata: status, headers, body, token usage, latency."""
    request = flow.request
    response = flow.response
    if not response:
        return

    # Only audit responses to AI requests (match by request_id stored in flow metadata)
    request_id = flow.metadata.get("agw_request_id")
    if not request_id:
        return

    # Calculate latency from request timestamp
    t0 = flow.metadata.get("agw_request_ts")
    latency_ms = int((time.time() - t0) * 1000) if t0 else None

    # Parse response body
    resp_body = response.get_content() or b""
    resp_str = resp_body.decode("utf-8", errors="replace")
    try:
        resp_json = json.loads(resp_str)
    except (json.JSONDecodeError, ValueError):
        resp_json = None

    # Extract token usage
    token_usage = {}
    if resp_json and isinstance(resp_json, dict):
        usage = resp_json.get("usage", {})
        if usage:
            token_usage = {
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            }

    # Redact sensitive response headers
    resp_headers = _redact_headers(dict(response.headers))

    event = {
        "event": "ai_response",
        "request_id": request_id,
        "response_status": response.status_code,
        "response_headers": resp_headers,
        "response_body": resp_json,
        "response_body_raw": resp_str[:4000],
        "token_usage": token_usage,
        "latency_ms": latency_ms,
        "summary": f"Response {response.status_code} ({latency_ms}ms)" if latency_ms else f"Response {response.status_code}",
    }
    gw.audit_log(event)
```

**同时修改 `request()` 钩子**：在 `request()` 末尾（`gw.audit_log(event)` 之后）存储 request_id 和时间戳到 flow metadata：

```python
# Store for response() hook
flow.metadata["agw_request_id"] = request_id
flow.metadata["agw_request_ts"] = t0
```

**关键设计点**：
- `flow.metadata` 是 mitmproxy 内置的 dict，request→response 之间持久化
- `request_id` 关联请求和响应事件，dashboard 已支持按 `request_id` 匹配
- `response_body` 存完整 JSON dict（dashboard `extract_tool_calls` 需要从中提取 assistant 的 tool_calls）
- `response_body_raw` 存截断字符串供预览
- SSE 流式响应：mitmproxy 5.3.0 在 `response()` 钩子中提供完整聚合 body

**验证**：
```bash
# 发送 AI 请求后检查审计日志
tail -2 audit/audit.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    d = json.loads(line)
    print(f'event={d[\"event\"]} status={d.get(\"response_status\")} tokens={d.get(\"token_usage\")} latency={d.get(\"latency_ms\")}')
"
# 应看到 ai_request_audited + ai_response 两条
```

### 2.2 I4 — 修复 _proc_cache 缓存结构

**文件**：`agw_addon.py`

**改动 1**：缓存写入（第 236-239 行）改为 6 元素：
```python
with gw._proc_cache_lock:
    gw._proc_cache[peer_port] = (
        agent_pid, agent_comm, app_name, agent_id, session_id, now,
    )
```

**改动 2**：缓存读取（第 150-154 行）改为读取 6 元素：
```python
now = time.time()
with gw._proc_cache_lock:
    cached = gw._proc_cache.get(peer_port)
    if cached and (now - cached[5]) < gw._proc_cache_ttl:
        return cached[0], cached[1], cached[2], cached[3], cached[4]
```

**改动 3**：`agentgatewayd.py:485` 的 `_proc_cache` 注释更新：
```python
_proc_cache = {}  # port → (pid, comm, app_name, agent_id, session_id, ts)
```

> 注意：`agentgatewayd.py` 的 `_lookup_peer_process()` 也使用 `_proc_cache`，但它写入的是 4 元素 `(pid, comm, app_name, now)`。由于 addon 和 agentgatewayd 的 main() 不会同时运行（mitmproxy 模式不运行 agentgatewayd main()），不会冲突。但如果要彻底干净，应在阶段 4 清理死代码时一并移除 `_lookup_peer_process()` 的缓存写入。

### 2.3 I5 — 手动纳入 cgroup 的进程生成稳定 agent_id

**文件**：`agw_addon.py`，在 `_lookup_peer()` 中，读取环境变量之后（第 226 行后）

**改动**：在 `app_name` 回退逻辑之后，增加 `agent_id` / `session_id` 回退：

```python
# Fall back to stable agent_id based on exe basename if env not set
if not agent_id and agent_pid:
    agent_id = f"agent-{app_name or agent_comm or 'unknown'}"
if not session_id and agent_pid:
    session_id = f"session-{app_name or agent_comm or 'unknown'}"
```

**原理**：
- 通过 `agw-admit.sh` 启动的进程有 `AGENTGATEWAY_AGENT_ID`（如 `agent-<uuid>`），优先使用
- 手动纳入 cgroup 的进程（如 omp）无环境变量，用 `agent-omp` 作为稳定 ID
- mitmproxy 重启后 agent_id 不变（基于 exe basename，不依赖随机 UUID）

**验证**：
```bash
# 手动纳入 omp 后发请求，检查 agent_id
tail -1 audit/audit.jsonl | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(f'agent_id={d[\"agent_id\"]}')"
# 应输出 agent-omp（而非 agent-<随机hex>）
```

### 2.4 I9 — audit_init() 重复调用文件句柄泄漏

**文件**：`agentgatewayd.py:119-124`

**改动**：
```python
def audit_init():
    global _audit_file
    if _audit_file:
        _audit_file.close()
    os.makedirs(AUDIT_DIR, exist_ok=True)
    path = os.path.join(AUDIT_DIR, "audit.jsonl")
    _audit_file = open(path, "a", buffering=1)  # line-buffered
    log(f"[AUDIT] Logging to {path}")
```

**验证**：语法检查 `python3 -c "import ast; ast.parse(open('gateway/agentgatewayd.py').read())"`

---

## 阶段 3：IPv6 归因 + 日志治理

### 3.1 I6 — _lookup_peer 支持 /proc/net/tcp6

**文件**：`agw_addon.py`，`_lookup_peer()` 中 /proc/net/tcp 读取部分（第 156-175 行）

**改动**：将 /proc/net/tcp 读取提取为辅助函数，同时扫描 tcp 和 tcp6：

```python
def _find_socket_inode(peer_port, exclude_port):
    """Find socket inode by local port in /proc/net/tcp and /proc/net/tcp6."""
    for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(proc_file) as f:
                f.readline()  # skip header
                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    if parts[3] != "01":  # ESTABLISHED
                        continue
                    l_port = int(parts[1].split(":")[1], 16)
                    if l_port != peer_port:
                        continue
                    r_port = int(parts[2].split(":")[1], 16)
                    if r_port == exclude_port:
                        continue
                    return parts[9]
        except OSError:
            continue
    return None
```

然后在 `_lookup_peer()` 中调用：
```python
client_inode = _find_socket_inode(peer_port, LISTEN_PORT)
```

### 3.2 I14 — request_body 截断策略

**文件**：`agw_addon.py:113-118`

**问题**：当前 `request_body` 存完整 dict（可能数十 KB），`request_body_raw` 存截断 2000 字符。两者重复。

**改动**：保留 `request_body` 为完整 dict（dashboard 需要提取 tools/tool_calls），但移除 `request_body_raw`（冗余）。用 `preview` 字段（已有，200 字符）替代预览需求。

```diff
-            "request_body": request_body,
-            "request_body_raw": body_str[:2000],
+            "request_body": request_body,
```

同时修改 dashboard `get_ai_requests()` 中 `request_body_raw` 的引用，改为从 `request_body` 生成预览：
```python
# In get_ai_requests, replace request_body_raw with generated preview
rb = req.get("request_body")
if rb and isinstance(rb, dict):
    msgs = rb.get("messages", [])
    # ... already have preview from event
```

**但考虑到审计完整性**，保留完整 `request_body` dict 是必要的（tools 定义和 tool_calls 历史都在 messages 中）。真正的日志膨胀问题通过阶段 3.3 的日志轮转解决。

**修正方案**：移除 `request_body_raw`（冗余），保留 `request_body` 完整 dict。dashboard 中 `request_body_raw` 的引用改为 `request_body` 的 JSON 字符串截断。

### 3.3 D6 — 审计日志轮转

**文件**：`agentgatewayd.py`，`audit_init()` 和 `audit_log()`

**改动**：在 `audit_init()` 中检查日志大小，超过阈值时轮转：

```python
def audit_init():
    global _audit_file
    if _audit_file:
        _audit_file.close()
    os.makedirs(AUDIT_DIR, exist_ok=True)
    path = os.path.join(AUDIT_DIR, "audit.jsonl")
    # Rotate if log exceeds 50MB
    if os.path.exists(path) and os.path.getsize(path) > 50 * 1024 * 1024:
        for i in range(4, 0, -1):
            old = f"{path}.{i}"
            older = f"{path}.{i+1}" if i < 4 else None
            if os.path.exists(old):
                if older:
                    os.rename(old, older)
                else:
                    os.remove(old)
        os.rename(path, f"{path}.1")
        log(f"[AUDIT] Rotated log (>{50}MB)")
    _audit_file = open(path, "a", buffering=1)
    log(f"[AUDIT] Logging to {path}")
```

**保留 5 个轮转文件**（`audit.jsonl` + `.1` ~ `.4`），每个最大 50MB，总上限 250MB。

dashboard `read_audit_events()` 也需读取轮转文件（或只读当前文件，接受历史数据不可见）。

### 3.4 I10 — dashboard 增加文件修改时间缓存

**文件**：`dashboard/dashboard.py:43-57`

**改动**：缓存读取结果，仅在文件修改时间变化时重新解析：

```python
_audit_cache = {"mtime": 0, "events": []}

def read_audit_events():
    """Read all audit events from the JSONL log (cached by mtime)."""
    if not os.path.exists(AUDIT_LOG):
        return []
    mtime = os.path.getmtime(AUDIT_LOG)
    if mtime == _audit_cache["mtime"]:
        return _audit_cache["events"]
    events = []
    with open(AUDIT_LOG, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    _audit_cache["mtime"] = mtime
    _audit_cache["events"] = events
    return events
```

**验证**：
```bash
# 连续两次调用 API，第二次应更快（缓存命中）
time curl -s http://127.0.0.1:9090/api/data > /dev/null
time curl -s http://127.0.0.1:9090/api/data > /dev/null
```

---

## 阶段 4：死代码清理 + 进程监控

### 4.1 I7 — 清理 agentgatewayd.py 死代码

**文件**：`agentgatewayd.py`

**删除以下代码**（仅被旧 transparent_proxy.py / CONNECT 代理路径使用）：

| 行范围 | 代码 | 删除原因 |
|--------|------|----------|
| 151-214 | `ToolCallTracker` 类 | agw_addon.py 不使用 |
| 218-286 | `load_ca()` / `generate_cert_for_host()` / CA 全局变量 | mitmproxy 自行管理 CA |
| 288-342 | `_upstream_pool` / `_get_upstream_socket()` / `_return_upstream_socket()` | 旧代理连接池 |
| 414-457 | `detect_app_source()` | agw_addon.py 不调用 |
| 459-481 | `detect_ai_response()` | agw_addon.py response() 自行解析 |
| 569-723 | `_lookup_peer_process()` | agw_addon.py 有自己的 `_lookup_peer()` |
| 726-1628 | `MITMProxyHandler` / `ThreadingHTTPProxyServer` / `make_handler_with_session()` / `main()` | 旧 CONNECT 代理主循环 |

**保留的代码**（addon 依赖）：
- 配置常量（AI_API_PATHS / AI_AUTH_HEADERS / AI_HOST_PATTERNS / AI_BODY_SIGNALS）
- `should_mitm()`（spec 保留供 CONNECT 代理路径）
- `audit_init()` / `audit_log()` / `log()`
- `detect_ai_request()`
- `_proc_cache` / `_proc_cache_lock` / `_proc_cache_ttl` / `_proc_scan_semaphore`
- `_TOOL_PROCESSES` / `_read_comm()` / `_read_ppid()` / `_resolve_agent_process()`

**同时删除** `from cryptography import ...` 四行导入（不再需要）。

**预计**：从 1628 行减少到 ~400 行。

**验证**：
```bash
python3 -c "import sys; sys.path.insert(0,'gateway'); import agentgatewayd; print('OK')"
python3 -c "import ast; ast.parse(open('gateway/agentgatewayd.py').read()); print('syntax OK')"
```

### 4.2 I13 — mitmproxy 进程监控/自动重启

**文件**：`start.sh`

**方案**：在 `do_start()` 中，用 `while true` 循环监控 mitmproxy 进程：

```bash
start_proc_with_watchdog() {
    local name="$1" cmd="$2" pidfile="$3" logfile="$4"
    if is_running "$pidfile"; then
        echo "[start.sh] $name already running (pid=$(cat "$pidfile"))."
        return 0
    fi
    echo "[start.sh] Starting $name with watchdog ..."
    bash -c '
        while true; do
            '"$cmd"'
            exit_code=$?
            if [[ $exit_code -eq 0 ]]; then
                echo "[watchdog] '"$name"' exited normally."
                break
            fi
            echo "[watchdog] '"$name"' crashed (exit=$exit_code), restarting in 2s..."
            sleep 2
        done
    ' >>"$logfile" 2>&1 &
    local pid=$!
    echo "$pid" > "$pidfile"
    echo "[start.sh] $name started (pid=$pid, log=$logfile, watchdog=on)."
}
```

**但需要谨慎**：mitmproxy 崩溃时 cgroup 内进程的连接被拒绝，自动重启后新连接恢复正常。但如果 mitmproxy 反复崩溃，会形成崩溃-重启循环。添加最大重启次数限制：

```bash
    bash -c '
        max_restarts=5
        restarts=0
        while [[ $restarts -lt $max_restarts ]]; do
            '"$cmd"'
            exit_code=$?
            if [[ $exit_code -eq 0 ]]; then
                break
            fi
            restarts=$((restarts + 1))
            echo "[watchdog] '"$name"' crashed (exit=$exit_code), restart $restarts/$max_restarts in 2s..."
            sleep 2
        done
        if [[ $restarts -ge $max_restarts ]]; then
            echo "[watchdog] '"$name"' exceeded max restarts ($max_restarts), giving up."
        fi
    ' >>"$logfile" 2>&1 &
```

**注意**：dashboard 不需要 watchdog（崩溃不影响其他进程）。

**验证**：
```bash
./start.sh restart
# 杀掉 mitmproxy 进程
kill $(cat logs/proxy.pid)
sleep 3
./start.sh status  # 应显示 running（watchdog 重启了）
tail -5 logs/proxy.log  # 应有 watchdog 重启日志
```

### 4.3 I11 — --cleanup 完整清理

**文件**：`setup_iptables.sh`，`--cleanup` 分支

**改动**：在删除 iptables 规则后，增加 cgroup 清理：

```bash
# Remove cgroup (move all tasks to root cgroup first)
if [[ -d "$CGROUP_DIR" ]]; then
    echo "[setup] Moving cgroup tasks to root..."
    while IFS= read -r pid; do
        echo "$pid" > /sys/fs/cgroup/net_cls/tasks 2>/dev/null || true
    done < "$CGROUP_DIR/tasks" 2>/dev/null
    rmdir "$CGROUP_DIR" 2>/dev/null && echo "[setup] Cgroup removed" || echo "[setup] Cgroup not empty, kept"
fi
```

**不卸载 `xt_cgroup` 模块**（其他系统服务可能依赖）。

---

## 阶段 5：Spec 文档修正

### 5.1 D1 — 修正"不可绕过"表述

**文件**：`specs/方案A_透明代理进程级拦截_4.19内核.md` §2

**改动**：将"不可绕过（内核 NAT 重定向）"改为：

```markdown
| 可绕过性 | Agent 可不尊重环境变量 | **有限强制**——cgroup 内进程的 :443 流量被内核重定向，但 Agent 可移出 cgroup 或使用非 443 端口 |
```

§6 限制与诚实边界表中增加：
```markdown
| 可被 Agent 绕过 | Agent 可移出 cgroup / 用非标端口 / QUIC | 需 6.6+ BPF-LSM 强制 |
```

### 5.2 D2 — 修正"零改造"表述

**文件**：`specs/方案A_透明代理进程级拦截_4.19内核.md` §1

**改动**：将"Agent 零改造——不设任何环境变量"改为：

```markdown
- **Agent 代码零改造**——不需要修改 Agent 源码，但需通过 agw-admit 启动或手动写入 cgroup
```

### 5.3 D3 — 补充 CA 信任链限制

**文件**：`specs/方案A_透明代理进程级拦截_4.19内核.md` §6

§6 限制与诚实边界表增加：
```markdown
| Java truststore 独立 | Java 应用不读取系统 CA | 需手动导入 `keytool -importcert` |
| Flatpak/Snap CA 命名空间 | 容器化应用有独立 CA | 需在容器内安装 |
```

### 5.4 D4 — 补充端口和协议限制

**文件**：`specs/方案A_透明代理进程级拦截_4.19内核.md` §6

§6 限制与诚实边界表增加：
```markdown
| 仅拦截 TCP :443/:8443/:9443 | 非 443 端口和 UDP/QUIC 流量不拦截 | 需扩展 iptables 端口列表或用 BPF |
| IPv6 不受 cgroup net_cls 约束 | IPv6 流量绕过拦截 | cgroup v1 net_cls 不标记 IPv6 socket |
```

### 5.5 D5 — 补充单点故障说明

**文件**：`specs/方案A_透明代理进程级拦截_4.19内核.md` §6

§6 限制与诚实边界表增加：
```markdown
| mitmproxy 单点故障 | 崩溃后 cgroup 进程 :443 连接被拒绝 | start.sh watchdog 自动重启（阶段 4.2 实现） |
```

### 5.6 D7 — 补充 /proc 扫描性能说明

**文件**：`specs/方案A_透明代理进程级拦截_4.19内核.md` §6

§6 限制与诚实边界表增加：
```markdown
| /proc 扫描 O(n×fd) | 高并发时进程归因延迟 | 30s 缓存 + 4 并发限制；6.6+ 可用 BPF sockmap |
```

---

## 执行顺序与依赖关系

```
阶段 1（快速修复）     ← 无依赖，可并行
  1.1 I1  start.sh CA 路径
  1.2 I2  setup_iptables.sh help 文本
  1.3 I8  setup_iptables.sh HOME 修正
  1.4 I12 agw-admit.sh 参数校验

阶段 2（核心功能）     ← 依赖阶段 1 完成（需重启 mitmproxy）
  2.1 I3  response() 钩子实现        ← 最高优先级
  2.2 I4  _proc_cache 缓存结构修复
  2.3 I5  稳定 agent_id 生成
  2.4 I9  audit_init() 句柄泄漏

阶段 3（日志治理）     ← 依赖阶段 2 完成
  3.1 I6  IPv6 /proc/net/tcp6 支持
  3.2 I14 request_body 截断策略
  3.3 D6  审计日志轮转
  3.4 I10 dashboard mtime 缓存

阶段 4（清理与健壮性）  ← 依赖阶段 3 完成
  4.1 I7  清理 agentgatewayd.py 死代码
  4.2 I13 mitmproxy watchdog 自动重启
  4.3 I11 --cleanup 完整清理

阶段 5（Spec 文档）    ← 依赖阶段 4 完成（反映最终实现）
  5.1-5.6 D1-D7 Spec 修正
```

## 验证清单

每个阶段完成后的验证项：

### 阶段 1 验证
- [ ] `./start.sh status` 不打印 CA WARNING
- [ ] `bash setup_iptables.sh -h` 显示正确 CA 路径
- [ ] `sudo bash setup_iptables.sh` 直接运行时 CA 安装成功（不依赖 `--preserve-env`）
- [ ] `./agw-admit.sh --app` 报错退出

### 阶段 2 验证
- [ ] AI 请求后审计日志出现 `ai_response` 事件
- [ ] `response_status` / `token_usage` / `latency_ms` 有值
- [ ] dashboard 请求列表 `has_response=true`
- [ ] dashboard 跟踪列表 `tool_call_count > 0`（有工具调用的对话）
- [ ] omp 请求的 `agent_id=agent-omp`（稳定，不随 mitmproxy 重启变化）
- [ ] 缓存命中时 `agent_id` 不为 None

### 阶段 3 验证
- [ ] IPv6 连接可归因（如有 IPv6 目标）
- [ ] 日志超过 50MB 时自动轮转
- [ ] dashboard 连续请求第二次更快（mtime 缓存命中）

### 阶段 4 验证
- [ ] `python3 -c "import sys; sys.path.insert(0,'gateway'); import agentgatewayd"` 成功
- [ ] agentgatewayd.py 行数 < 500
- [ ] `cryptography` 不再被 import
- [ ] kill mitmproxy 后 2s 内自动重启
- [ ] `sudo bash setup_iptables.sh --cleanup` 清理 cgroup

### 阶段 5 验证
- [ ] Spec 中无"不可绕过"表述
- [ ] Spec 中无"不设任何环境变量"表述
- [ ] Spec §6 包含所有新增限制项

## 不修复的项（明确放弃）

| 缺陷 | 原因 |
|------|------|
| D1 完全不可绕过 | 需要 6.6+ BPF-LSM，超出 4.19 内核能力 |
| D4 完整端口覆盖 | 端口枚举是 4.19 方案的固有限制，BPF 方案才能解决 |
| D3 Java/Flatpak CA | 按需手动导入，不是通用问题 |
