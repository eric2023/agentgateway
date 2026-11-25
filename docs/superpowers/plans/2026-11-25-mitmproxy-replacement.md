# 实施计划：用 mitmproxy 替代 transparent_proxy.py

> **Spec**: 方案B — mitmproxy 替代自研代理
> **创建**: 2026-11-25
> **状态**: 待确认

---

## 1. 背景与目标

### 问题

当前 transparent_proxy.py 存在致命缺陷：
- **流式响应被破坏**：`_do_forward()` 全缓冲上游响应，SSE 流式不可用
- **无 HTTP/2 支持**：只处理 HTTP/1.1
- **无 WebSocket 支持**：不处理 Upgrade 头
- 进程归因竞态、单点瓶颈等

### 目标

用 mitmproxy 5.3.0 替代 transparent_proxy.py，一次性解决流式/HTTP/2/WebSocket。
保留 cgroup + iptables 进程隔离、agentgatewayd.py 的 AI 识别 + 审计、dashboard。

### 环境确认

| 项目 | 状态 |
|------|------|
| mitmproxy 5.3.0 | ✅ 已安装（python3.7） |
| `mitmdump` 命令 | ✅ 可用 |
| `--mode transparent` | ✅ 支持 |
| HTTP/2 (`http2: True`) | ✅ 默认开启 |
| WebSocket (`websocket: True`) | ✅ 默认开启 |
| `flow.client_conn.address` | ✅ 返回客户端 (ip, port)，用于进程归因 |
| `flow.client_conn.connection` | ✅ 原始 socket，可 `.getpeername()` |

---

## 2. 变更范围

### 新建文件

| 文件 | 用途 |
|------|------|
| `gateway/agw_addon.py` | mitmproxy addon：AI 请求识别 + 审计 + 进程归因 |

### 修改文件

| 文件 | 改动 |
|------|------|
| `start.sh` | 启动 `mitmdump` 替代 `python3 transparent_proxy.py` |
| `setup_iptables.sh` | CA 安装改为安装 mitmproxy 的 CA |
| `README.md` | 更新架构说明 |
| `specs/方案A_透明代理进程级拦截_4.19内核.md` | 更新代理层描述 |

### 废弃文件

| 文件 | 处理 |
|------|------|
| `gateway/transparent_proxy.py` | 删除（mitmproxy 完全替代） |

### 保留不变

| 文件 | 原因 |
|------|------|
| `agw-admit.sh` | cgroup 纳入逻辑不变 |
| `dashboard/dashboard.py` | 读取 audit.jsonl 不变 |
| `gateway/agentgatewayd.py` | agw_addon.py 复用其 detect_ai_request / audit_log / _resolve_agent_process |
| `setup_iptables.sh` 的 iptables 规则 | cgroup + REDIRECT 逻辑不变 |

---

## 3. 详细设计

### 3.1 `gateway/agw_addon.py`

mitmproxy addon，复用 agentgatewayd.py 的核心能力。

**核心逻辑**：

```python
from mitmproxy import http, ctx
import sys, os, time, uuid, json, socket

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agentgatewayd as gw


class AgentGatewayAddon:
    def __init__(self):
        gw.audit_init()
        gw.load_ca()
        self.agent_id = os.environ.get("AGENTGATEWAY_AGENT_ID",
                                       f"agent-{uuid.uuid4().hex[:8]}")
        self.session_id = os.environ.get("AGENTGATEWAY_SESSION_ID",
                                         f"session-{uuid.uuid4().hex[:8]}")
        self.request_id_prefix = f"req-{uuid.uuid4().hex[:8]}"
        ctx.log.info(f"AgentGateway addon loaded: agent={self.agent_id}")

    def request(self, flow: http.HTTPFlow):
        method = flow.request.method
        path = flow.request.path
        headers = dict(flow.request.headers)
        body = flow.request.get_content() or b""
        host = flow.request.pretty_host
        port = flow.request.port

        is_ai, confidence, signals, detail = gw.detect_ai_request(
            method, path, headers, body
        )

        if not is_ai:
            return

        # 进程归因
        peer_pid, peer_comm, peer_app, peer_agent, peer_session = \
            self._lookup_peer(flow)

        audit_app = peer_app or peer_comm or "transparent"
        audit_agent = peer_agent or self.agent_id
        audit_session = peer_session or self.session_id
        request_id = f"{self.request_id_prefix}-{uuid.uuid4().hex[:6]}"

        event = {
            "event": "ai_request_audited",
            "decision": "AUDIT",
            "app_name": audit_app,
            "session_id": audit_session,
            "agent_id": audit_agent,
            "request_id": request_id,
            "method": method,
            "host": host,
            "port": port,
            "path": path,
            "model": detail.get("model", ""),
            "confidence": confidence,
            "signals": signals,
            "preview": detail.get("preview", ""),
            "prompt_len": detail.get("prompt_len", 0),
            "request_headers": _redact_headers(headers),
            "request_body": body.decode("utf-8", errors="replace")[:2000],
            "stream_mode": "stream" in body.decode("utf-8", errors="replace").lower(),
            "source": "mitmproxy_addon",
            "summary": f"AI request audited & forwarded: {method} {host}{path} model={detail.get('model','')}",
        }
        gw.audit_log(event)

    def response(self, flow: http.HTTPFlow):
        """可选：记录响应状态和 token usage"""
        # 如果需要记录响应，可以在这里实现
        pass

    def _lookup_peer(self, flow):
        """进程归因：从 flow.client_conn 获取客户端源端口，
        通过 /proc/net/tcp 匹配 socket inode → PID → 环境变量"""
        client = flow.client_conn
        peer_port = client.address[1]

        # 检查缓存
        now = time.time()
        with gw._proc_cache_lock:
            cached = gw._proc_cache.get(peer_port)
            if cached and (now - cached[3]) < gw._proc_cache_ttl:
                return cached[0], cached[1], cached[2], None, None

        # 通过 /proc/net/tcp 匹配客户端 socket
        # 客户端侧：local=peer_port, remote=<orig_dst>:<port>
        # 排除代理自身的监听端口 (8444)
        client_inode = None
        proxy_port = 8444
        try:
            with open("/proc/net/tcp") as f:
                f.readline()
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
                    if r_port == proxy_port:
                        continue
                    client_inode = parts[9]
                    break
        except OSError:
            return None, None, None, None, None

        if not client_inode:
            return None, None, None, None, None

        # 扫描 /proc/*/fd/ 找 PID
        search_link = f"socket:[{client_inode}]"
        pid = None
        with gw._proc_scan_semaphore:
            my_pid = os.getpid()
            for pid_str in os.listdir("/proc"):
                if not pid_str.isdigit() or int(pid_str) == my_pid:
                    continue
                fd_dir = f"/proc/{pid_str}/fd"
                try:
                    for fd in os.listdir(fd_dir):
                        try:
                            if os.readlink(f"{fd_dir}/{fd}") == search_link:
                                pid = int(pid_str)
                                break
                        except OSError:
                            continue
                except OSError:
                    continue
                if pid:
                    break

        if pid is None:
            return None, None, None, None, None

        agent_pid, agent_comm = gw._resolve_agent_process(pid)

        # 读 AGENTGATEWAY_* 环境变量
        app_name = agent_id = session_id = None
        try:
            with open(f"/proc/{pid}/environ", "rb") as f:
                env = f.read()
            for entry in env.split(b"\x00"):
                if entry.startswith(b"AGENTGATEWAY_APP_NAME="):
                    app_name = entry.split(b"=", 1)[1].decode("utf-8", "replace")
                elif entry.startswith(b"AGENTGATEWAY_AGENT_ID="):
                    agent_id = entry.split(b"=", 1)[1].decode("utf-8", "replace")
                elif entry.startswith(b"AGENTGATEWAY_SESSION_ID="):
                    session_id = entry.split(b"=", 1)[1].decode("utf-8", "replace")
        except OSError:
            pass

        with gw._proc_cache_lock:
            gw._proc_cache[peer_port] = (agent_pid, agent_comm, app_name, now)

        return agent_pid, agent_comm, app_name, agent_id, session_id


def _redact_headers(headers):
    out = {}
    for k, v in headers.items():
        if k.lower() in ("authorization", "x-api-key", "cookie", "x-goog-api-key"):
            out[k] = (v[:20] + "***REDACTED***") if v else v
        else:
            out[k] = v
    return out


addons = [AgentGatewayAddon()]
```

### 3.2 CA 证书策略

**决策**：用 mitmproxy 自己的 CA，安装到系统。

mitmproxy 首次启动时自动在 `~/.mitmproxy/` 生成 CA：
- `mitmproxy-ca-cert.pem` — CA 证书（安装到系统）
- `mitmproxy-ca.pem` — CA 证书 + 私钥

**setup_iptables.sh 改动**：

```bash
# 旧：
CA_SRC="$SCRIPT_DIR/certs/ca-cert.pem"
CA_DST="/etc/ssl/certs/agentgateway-ca.pem"

# 新：
# 先运行一次 mitmdump 生成 CA（如果不存在）
if [[ ! -f "$HOME/.mitmproxy/mitmproxy-ca-cert.pem" ]]; then
    timeout 2 mitmdump --quiet 2>/dev/null || true
fi
CA_SRC="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
CA_DST="/etc/ssl/certs/agentgateway-ca.pem"
```

**不再需要** `gateway/gen_ca.py`（mitmproxy 自动生成 CA）。

### 3.3 `start.sh` 改动

```bash
# 旧：
TPROXY="$PROJECT_DIR/gateway/transparent_proxy.py"
start_proc "transparent-proxy" "$TPROXY" "$TPROXY_PIDFILE" "$TPROXY_LOG"

# 新：
MITMDUMP="$(command -v mitmdump || true)"
ADDON="$PROJECT_DIR/gateway/agw_addon.py"
# start_proc 需要改为支持带参数的命令
```

`start_proc` 改为直接执行命令字符串：

```bash
start_proc() {
    local name="$1" cmd="$2" pidfile="$3" logfile="$4"
    if is_running "$pidfile"; then
        echo "[start.sh] $name already running (pid=$(cat "$pidfile"))."
        return 0
    fi
    echo "[start.sh] Starting $name ..."
    bash -c "$cmd" >>"$logfile" 2>&1 &
    local pid=$!
    echo "$pid" > "$pidfile"
    echo "[start.sh] $name started (pid=$pid, log=$logfile)."
}
```

启动命令：

```bash
start_proc "mitmproxy" \
    "mitmdump --mode transparent --listen-host 127.0.0.1 --listen-port 8444 \
     --set ssl_insecure=true \
     -s $ADDON" \
    "$TPROXY_PIDFILE" "$TPROXY_LOG"
```

### 3.4 agentgatewayd.py 清理

agw_addon.py 仍需 import agentgatewayd.py 复用以下函数：

| 函数 | 保留 | 原因 |
|------|------|------|
| `detect_ai_request()` | ✅ | AI 请求识别 |
| `audit_log()` / `audit_init()` | ✅ | 审计日志 |
| `load_ca()` | ✅ | addon 初始化时加载（可能不需要） |
| `_resolve_agent_process()` | ✅ | 父进程链遍历 |
| `_proc_cache` / `_proc_cache_lock` / `_proc_cache_ttl` | ✅ | 进程缓存 |
| `_proc_scan_semaphore` | ✅ | 并发限制 |
| `_read_comm()` / `_read_ppid()` | ✅ | 进程信息读取 |
| `log()` | ✅ | 日志输出 |
| `_TOOL_PROCESSES` | ✅ | 工具进程列表 |
| `generate_cert_for_host()` | ❌ | mitmproxy 自己签发证书 |
| `_get_upstream_socket()` / `_return_upstream_socket()` | ❌ | mitmproxy 内置连接池 |
| `MITMProxyHandler` / `ThreadingHTTPProxyServer` | ❌ | 不再需要 |
| `_lookup_peer_process()` | ❌ | agw_addon 有自己的实现 |
| `main()` | ❌ | 不再独立运行 |

**不删 agentgatewayd.py**，仅标注哪些函数不再被使用。后续可逐步清理。

---

## 4. 实施步骤

### Task 1: 创建 `gateway/agw_addon.py`
- 复用 agentgatewayd.py 的 detect_ai_request / audit_log / _resolve_agent_process
- 实现 _lookup_peer（从 flow.client_conn.address 获取客户端端口）
- 实现 _redact_headers
- 导出 `addons = [AgentGatewayAddon()]`

### Task 2: 修改 `start.sh`
- 改 start_proc 支持命令字符串
- 启动 mitmdump --mode transparent --listen-port 8444 -s agw_addon.py
- 保留 dashboard 启动不变

### Task 3: 修改 `setup_iptables.sh`
- CA 安装改为 mitmproxy CA（~/.mitmproxy/mitmproxy-ca-cert.pem）
- 首次运行时生成 mitmproxy CA
- 保留 iptables 多端口规则不变

### Task 4: 删除 `gateway/transparent_proxy.py`
- mitmproxy 完全替代

### Task 5: 更新文档
- README.md：更新架构图和代理描述
- specs/方案A：更新 3.3 节代理描述

### Task 6: 验证
- 启动 mitmdump + addon
- agw-admit.sh --app TestApp curl AI 请求 → 审计正确
- 测试 SSE 流式（stream:true）→ 流式正常
- 测试非 Agent 进程不受影响

---

## 5. 风险与缓解

| 风险 | 缓解 |
|------|------|
| mitmproxy 5.3.0 是 2020 版本 | 4.19 内核 + python3.7 环境，5.3.0 是最高兼容版本 |
| 依赖冲突（click 降级） | 仅影响 black/spdx-scanner 等开发工具，不影响运行 |
| 进程归因竞态 | 与旧方案相同，后续可用 SO_PEERSEC 改进 |
| mitmproxy CA 与旧 CA 不同 | setup 脚本自动安装新 CA，旧 CA 可保留不冲突 |
| mitmdump 以 root 运行 | 与旧 transparent_proxy.py 相同，root 不在 cgroup 中 |
