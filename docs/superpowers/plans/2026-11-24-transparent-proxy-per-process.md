# 透明代理进程级拦截 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用 iptables REDIRECT + cgroup net_cls 进程级隔离替换环境注入方式，实现零改造、不可绕过的 Agent HTTPS 请求拦截。

**Architecture:** trustexec 将 Agent 进程写入 cgroup net_cls（classid 0x100001），iptables-legacy 匹配 cgroup 重定向 :443 到 :8444，transparent_proxy.py MITM 全部流量并复用 agentgatewayd 的 CA/L7/审计/连接池。系统级 CA 安装后全局信任。

**Tech Stack:** Python 3.8+ stdlib + cryptography, iptables-legacy, cgroup v1 net_cls, systemd

## Global Constraints

- 目标内核：4.19.0-amd64-desktop
- iptables 版本：iptables v1.8.2 (nf_tables)，但必须用 `iptables-legacy`（支持 `-m cgroup`）
- 内核模块：`xt_cgroup.ko` 位于 `/lib/modules/4.19.0-amd64-desktop/kernel/net/netfilter/xt_cgroup.ko`，需 `modprobe` 加载
- cgroup v1 `net_cls` 子系统位于 `/sys/fs/cgroup/net_cls/`
- 透明代理端口：8444（iptables REDIRECT 目标），仪表盘端口：9090
- `SO_ORIGINAL_DST = 80`, `SOL_IP = 0`（4.19 内核常量，Python socket 模块未导出）
- root 权限需求：modprobe、创建 cgroup、设置 iptables、安装系统级 CA
- 透明代理以 root 运行（避免 cgroup 匹配导致环路）

---

## File Structure

| 文件 | 责任 | 操作 |
|---|---|---|
| `gateway/transparent_proxy.py` | 透明代理，MITM 全部 cgroup 流量 | 修改 |
| `gateway/agentgatewayd.py` | 共享模块：CA/L7/审计/连接池 | 修改（删除 gsettings 代码） |
| `trustexec.sh` | Agent cgroup 纳入 | 改造 |
| `setup_iptables.sh` | 一次性 root 设置 | 新建 |
| `start.sh` | 生命周期管理 | 修改 |
| `specs/方案A_透明代理进程级拦截_4.19内核.md` | 新 spec | 已写 |
| `specs/方案A_用户态验证_4.19内核.md` | 旧 spec | 删除 |
| `specs/方案B_BPF-LSM内核级管控_6.6内核.md` | 旧 spec | 删除 |
| `gateway/libauditshim.c` | LD_PRELOAD shim 源码 | 删除 |
| `gateway/libauditshim.so` | 编译产物 | 删除 |

---

### Task 1: 删除废弃组件和旧 spec

**Files:**
- Delete: `specs/方案A_用户态验证_4.19内核.md`
- Delete: `specs/方案B_BPF-LSM内核级管控_6.6内核.md`
- Delete: `gateway/libauditshim.c`
- Delete: `gateway/libauditshim.so`

**Interfaces:**
- Consumes: 无
- Produces: 清理后的仓库，无历史方案残留

- [ ] **Step 1: 删除旧 spec 文件**

```bash
cd /home/ut000520@uos/Desktop/agentos/agentgateway
git rm specs/方案A_用户态验证_4.19内核.md
git rm specs/方案B_BPF-LSM内核级管控_6.6内核.md
```

- [ ] **Step 2: 删除 libauditshim 源码和编译产物**

```bash
git rm gateway/libauditshim.c
git rm -f gateway/libauditshim.so 2>/dev/null || true
```

- [ ] **Step 3: 提交**

```bash
git add -A
git commit -m "refactor: 删除旧方案 spec 和 libauditshim（被透明代理 + 系统级 CA 替代）"
```

---

### Task 2: 修复 transparent_proxy.py — 全部 MITM + poll + 连接池

**Files:**
- Modify: `gateway/transparent_proxy.py`

**Interfaces:**
- Consumes: `gw.generate_cert_for_host()`, `gw.detect_ai_request()`, `gw.audit_log()`, `gw._get_upstream_socket()`, `gw._return_upstream_socket()`, `gw._dechunk()`
- Produces: 可运行的透明代理，全部流量 MITM，无 FD 限制，有连接池

- [ ] **Step 1: 修复 _handle — 移除 should_mitm 调用，全部 MITM**

当前 `_handle` 函数（约 line 319-344）调用 `gw._should_mitm(sni)` 判断是否 MITM。cgroup 隔离后全部 MITM。

将 `_handle` 函数改为：
```python
def _handle(client, addr):
    try:
        client.settimeout(15)
        first = client.recv(4096, socket.MSG_PEEK)
        if not first:
            return
        sni = extract_sni(first)
        orig_ip, orig_port = _orig_dst(client)
        if not sni:
            # No SNI: blind tunnel to the original destination.
            if orig_ip:
                client.recv(4096)
                _blind_tunnel(client, orig_ip, orig_port)
            return
        gw.log(f"[TPROXY] MITM {sni} from {addr[0]}:{addr[1]}")
        _mitm(client, sni)
    except (OSError, ssl.SSLError):
        pass
    finally:
        try:
            client.close()
        except OSError:
            pass
```

关键变更：移除 `if gw._should_mitm(sni):` 分支，所有有 SNI 的连接全部走 `_mitm`。

- [ ] **Step 2: 修复 _blind_tunnel — 改用 select.poll()**

当前 `_blind_tunnel`（约 line 197-225）和 `_select`（约 line 228-230）用 `select.select()`，FD 超 1024 时崩溃。

替换 `_select` 函数和 `_blind_tunnel` 为：
```python
def _blind_tunnel(client, host, port, initial=b""):
    try:
        remote = socket.create_connection((host, port), timeout=30)
    except Exception as e:
        gw.log(f"[TPROXY] blind tunnel to {host}:{port} failed: {e}")
        return
    try:
        if initial:
            remote.sendall(initial)
        poller = select.poll()
        poller.register(client, select.POLLIN | select.POLLERR | select.POLLHUP)
        poller.register(remote, select.POLLIN | select.POLLERR | select.POLLHUP)
        fd_to_sock = {client.fileno(): client, remote.fileno(): remote}
        while True:
            events = poller.poll(60000)
            if not events:
                break
            for fd, event in events:
                sock = fd_to_sock[fd]
                if event & (select.POLLERR | select.POLLHUP):
                    return
                if event & select.POLLIN:
                    data = sock.recv(65536)
                    if not data:
                        return
                    if sock is client:
                        remote.sendall(data)
                    else:
                        client.sendall(data)
    except (OSError, ssl.SSLError):
        pass
    finally:
        try:
            remote.close()
        except OSError:
            pass
```

删除 `_select` 函数（不再需要）。在文件顶部 `import select`。

- [ ] **Step 3: 重写 _forward — 使用连接池 + keep-alive + chunked 读取**

当前 `_forward`（约 line 151-194）每次新建 TLS 连接、`Connection: close`、简单拼接响应。

替换为：
```python
def _forward(host, port, method, path, headers, body):
    """Forward request upstream using pooled TLS connection."""
    sock, is_reused = gw._get_upstream_socket(host, port)
    try:
        return _do_forward(host, port, sock, method, path, headers, body)
    except (socket.timeout, ConnectionError, ssl.SSLError, OSError) as e:
        try:
            sock.close()
        except OSError:
            pass
        if not is_reused:
            raise
        gw.log(f"[POOL] Retrying {host}:{port} with fresh connection after: {e}")
        sock, _ = gw._get_upstream_socket(host, port)
        return _do_forward(host, port, sock, method, path, headers, body)


def _do_forward(host, port, sock, method, path, headers, body):
    """Send request on sock, read response, return socket to pool."""
    req = f"{method} {path} HTTP/1.1\r\n".encode("utf-8")
    for k, v in headers.items():
        if k.lower() in ("proxy-connection", "proxy-authorization", "connection"):
            continue
        req += f"{k}: {v}\r\n".encode("utf-8")
    req += b"Connection: keep-alive\r\n\r\n"
    req += body

    sock.sendall(req)

    resp_buf = b""
    while b"\r\n\r\n" not in resp_buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("upstream closed before headers")
        resp_buf += chunk

    hdr_end = resp_buf.find(b"\r\n\r\n")
    header_block = resp_buf[:hdr_end].decode("utf-8", errors="replace")
    body_data = resp_buf[hdr_end + 4:]

    lines = header_block.split("\r\n")
    try:
        _, status_str, _ = lines[0].split(" ", 2)
        status = int(status_str)
    except (IndexError, ValueError):
        status = 502

    resp_headers = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            resp_headers.append((k.strip(), v.strip()))

    content_length = None
    is_chunked = False
    connection_close = False
    for k, v in resp_headers:
        kl = k.lower()
        if kl == "content-length":
            try:
                content_length = int(v)
            except ValueError:
                pass
        elif kl == "transfer-encoding" and "chunked" in v.lower():
            is_chunked = True
        elif kl == "connection" and "close" in v.lower():
            connection_close = True

    if is_chunked:
        terminator = b"0\r\n\r\n"
        while not body_data.endswith(terminator):
            chunk = sock.recv(65536)
            if not chunk:
                break
            body_data += chunk
        body_data = gw._dechunk(body_data)
    elif content_length is not None:
        while len(body_data) < content_length:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body_data += chunk
    else:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body_data += chunk
        connection_close = True

    if connection_close:
        try:
            sock.close()
        except OSError:
            pass
    else:
        gw._return_upstream_socket(host, port, sock)

    return status, resp_headers, body_data
```

- [ ] **Step 4: 更新文件头注释**

将文件头注释（line 1-16）更新为：
```python
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
#
# AgentGateway transparent proxy (方案 A).
#
# Accepts iptables-REDIRECTed :443 traffic from cgroup-isolated Agent
# processes, extracts the SNI hostname from the TLS ClientHello, MITMs
# all connections (reusing agentgatewayd's CA/L7/audit/connection pool).
# Runs on :8444.
#
# iptables-legacy (root), redirecting cgroup 0x100001 :443 -> :8444:
#   /usr/sbin/iptables-legacy -t nat -A OUTPUT \
#     -p tcp --dport 443 -m cgroup --cgroup 0x100001 \
#     -j REDIRECT --to-port 8444
```

- [ ] **Step 5: 验证 transparent_proxy.py 可启动**

```bash
cd /home/ut000520@uos/Desktop/agentos/agentgateway
timeout 3 python3 gateway/transparent_proxy.py 2>&1
```
Expected: 显示 `[TPROXY] AgentGateway transparent proxy listening on 127.0.0.1:8444` 并正常退出。

- [ ] **Step 6: 提交**

```bash
git add gateway/transparent_proxy.py
git commit -m "refactor: transparent_proxy 全部MITM + poll() + 连接池"
```

---

### Task 3: 改造 trustexec.sh — cgroup 纳入

**Files:**
- Modify: `trustexec.sh`

**Interfaces:**
- Consumes: `/sys/fs/cgroup/net_cls/agentgateway/tasks`（需 setup 脚本创建并 chmod 666）
- Produces: Agent 进程在 cgroup 内，设置 AGENTGATEWAY_AGENT_ID/SESSION_ID 环境变量

- [ ] **Step 1: 重写 trustexec.sh**

将整个 trustexec.sh 替换为：
```bash
#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
#
# AgentGateway trustexec — Agent wrapper that admits the process into
# the iptables net_cls cgroup for transparent proxy interception.
#
# Usage: trustexec.sh [--app <name>] [--agent-id <uuid>] <command> [args...]
#
# Sets:
#   AGENTGATEWAY_AGENT_ID     → unique per-launch agent ID
#   AGENTGATEWAY_SESSION_ID   → unique per-launch session ID
#
# The process is written into /sys/fs/cgroup/net_cls/agentgateway/tasks,
# causing its :443 outbound traffic to be redirected by iptables to the
# transparent proxy on :8444. No environment proxy variables are set.

set -e

CGROUP_TASKS="/sys/fs/cgroup/net_cls/agentgateway/tasks"

# Defaults
APP_NAME="unknown"
AGENT_ID=""
SESSION_ID=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --app)
            APP_NAME="$2"
            shift 2
            ;;
        --agent-id)
            AGENT_ID="$2"
            shift 2
            ;;
        --session-id)
            SESSION_ID="$2"
            shift 2
            ;;
        --bpf)
            # Ignored: BPF mode was for 方案B (6.6 kernel), not applicable on 4.19
            shift
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "[trustexec] Unknown option: $1" >&2
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 [--app <name>] [--agent-id <uuid>] <command> [args...]"
    exit 1
fi

# Generate IDs if not provided
if [[ -z "$AGENT_ID" ]]; then
    AGENT_ID="agent-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4().hex[:8])')"
fi
if [[ -z "$SESSION_ID" ]]; then
    SESSION_ID="session-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4().hex[:8])')"
fi

# Set AgentGateway identity (read by transparent_proxy.py for audit attribution)
export AGENTGATEWAY_AGENT_ID="$AGENT_ID"
export AGENTGATEWAY_SESSION_ID="$SESSION_ID"
export AGENTGATEWAY_APP_NAME="$APP_NAME"

# Admit this process into the net_cls cgroup
if [[ -w "$CGROUP_TASKS" ]]; then
    echo $$ > "$CGROUP_TASKS"
else
    echo "[trustexec] WARNING: cannot write to $CGROUP_TASKS" >&2
    echo "[trustexec] Run setup_iptables.sh first to create the cgroup." >&2
fi

echo "[agentgateway] Agent ID:   $AGENT_ID"
echo "[agentgateway] Session ID: $SESSION_ID"
echo "[agentgateway] App:        $APP_NAME"
echo "[agentgateway] Cgroup:     $CGROUP_TASKS"
echo "[agentgateway] Command:    $@"
echo "[agentgateway] ─────────────────────────────────"

exec "$@"
```

- [ ] **Step 2: 验证 trustexec.sh 语法**

```bash
bash -n trustexec.sh
```
Expected: 无输出（语法正确）。

- [ ] **Step 3: 提交**

```bash
git add trustexec.sh
git commit -m "refactor: trustexec 从环境注入改为 cgroup net_cls 纳入"
```

---

### Task 4: 创建 setup_iptables.sh — 一次性 root 设置

**Files:**
- Create: `setup_iptables.sh`

**Interfaces:**
- Consumes: `certs/ca-cert.pem`（CA 证书）
- Produces: cgroup `net_cls/agentgateway` + iptables 规则 + 系统级 CA 安装

- [ ] **Step 1: 创建 setup_iptables.sh**

```bash
cat > setup_iptables.sh << 'SCRIPT'
#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
#
# One-time root setup for AgentGateway transparent proxy:
#   1. modprobe xt_cgroup
#   2. Create cgroup net_cls/agentgateway (classid 0x100001)
#   3. chmod 666 tasks (allow non-root trustexec to write)
#   4. Install system-level CA
#   5. Set iptables-legacy REDIRECT rule

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IPTABLES="/usr/sbin/iptables-legacy"
CGROUP_DIR="/sys/fs/cgroup/net_cls/agentgateway"
CLASSID="0x100001"
REDIRECT_PORT=8444

# ─── 1. Load kernel module ─────────────────────────────────────────────────
echo "[setup] Loading xt_cgroup module..."
modprobe xt_cgroup 2>/dev/null || {
    echo "[setup] WARNING: modprobe xt_cgroup failed — cgroup match may not work"
}

# ─── 2. Create cgroup ──────────────────────────────────────────────────────
echo "[setup] Creating cgroup $CGROUP_DIR..."
mkdir -p "$CGROUP_DIR"
echo "$CLASSID" > "$CGROUP_DIR/net_cls.classid"

# ─── 3. Allow non-root processes to join ───────────────────────────────────
chmod 666 "$CGROUP_DIR/tasks"
echo "[setup] cgroup tasks writable by all users"

# ─── 4. Install system-level CA ────────────────────────────────────────────
CA_SRC="$SCRIPT_DIR/certs/ca-cert.pem"
CA_DST="/etc/ssl/certs/agentgateway-ca.pem"
if [[ -f "$CA_SRC" ]]; then
    echo "[setup] Installing CA to $CA_DST..."
    cp "$CA_SRC" "$CA_DST"
    chmod 644 "$CA_DST"
    update-ca-certificates 2>/dev/null || true
    echo "[setup] System CA installed"
else
    echo "[setup] WARNING: $CA_SRC not found — run 'python3 gateway/gen_ca.py' first"
fi

# Also install to NSS DB for Chrome/Chromium
if command -v certutil &>/dev/null; then
    NSSDB="$HOME/.pki/nssdb"
    mkdir -p "$NSSDB"
    certutil -d "sql:$NSSDB" -A -t "C," -n "AgentGateway Root CA" -i "$CA_SRC" 2>/dev/null || true
    echo "[setup] NSS DB CA installed"
fi

# ─── 5. Set iptables rule ──────────────────────────────────────────────────
echo "[setup] Setting iptables-legacy REDIRECT rule..."

# Remove old rule if exists (ignore errors)
$IPTABLES -t nat -D OUTPUT \
    -p tcp --dport 443 -m cgroup --cgroup "$CLASSID" \
    -j REDIRECT --to-port "$REDIRECT_PORT" 2>/dev/null || true

# Add rule
$IPTABLES -t nat -A OUTPUT \
    -p tcp --dport 443 -m cgroup --cgroup "$CLASSID" \
    -j REDIRECT --to-port "$REDIRECT_PORT"

echo "[setup] iptables rule set: cgroup $CLASSID :443 → :$REDIRECT_PORT"
echo "[setup] ─────────────────────────────────────"
echo "[setup] Setup complete."
echo "[setup] Verify: $IPTABLES -t nat -L OUTPUT -n"
echo "[setup] Cleanup: bash $0 --cleanup"

# ─── Cleanup mode ──────────────────────────────────────────────────────────
if [[ "${1:-}" == "--cleanup" ]]; then
    echo "[setup] Removing iptables rule..."
    $IPTABLES -t nat -D OUTPUT \
        -p tcp --dport 443 -m cgroup --cgroup "$CLASSID" \
        -j REDIRECT --to-port "$REDIRECT_PORT" 2>/dev/null || true
    echo "[setup] iptables rule removed"
    exit 0
fi
SCRIPT
chmod +x setup_iptables.sh
```

> 注意：上面的 `cat > ... << 'SCRIPT'` 块是创建文件的说明性伪代码。实际实现时用 `write` 工具创建文件。

- [ ] **Step 2: 验证脚本语法**

```bash
bash -n setup_iptables.sh
```
Expected: 无输出。

- [ ] **Step 3: 提交**

```bash
git add setup_iptables.sh
git commit -m "feat: 新建 setup_iptables.sh 一次性 root 设置脚本"
```

---

### Task 5: 扩展 start.sh — 透明代理模式

**Files:**
- Modify: `start.sh`

**Interfaces:**
- Consumes: `gateway/transparent_proxy.py`, `dashboard/dashboard.py`, `setup_iptables.sh`
- Produces: 启动/停止透明代理 + 仪表盘，setup 子命令

- [ ] **Step 1: 修改 start.sh 变量和路径**

在 start.sh 顶部添加 transparent_proxy 变量，移除 gsettings 相关逻辑：

```bash
#!/bin/bash
# start.sh — Start AgentGateway transparent proxy + Dashboard.
#
# Usage:
#   ./start.sh start      # start transparent proxy + dashboard (background)
#   ./start.sh fg         # start in foreground (Ctrl+C to stop both)
#   ./start.sh stop       # stop both
#   ./start.sh restart    # restart both
#   ./start.sh status     # show running status
#   ./start.sh setup      # one-time root setup (iptables + cgroup + CA)

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
TPROXY="$PROJECT_DIR/gateway/transparent_proxy.py"
DASHBOARD="$PROJECT_DIR/dashboard/dashboard.py"
LOG_DIR="$PROJECT_DIR/logs"
TPROXY_LOG="$LOG_DIR/tproxy.log"
DASHBOARD_LOG="$LOG_DIR/dashboard.log"
TPROXY_PIDFILE="$LOG_DIR/tproxy.pid"
DASHBOARD_PIDFILE="$LOG_DIR/dashboard.pid"

PYTHON="$(command -v python3 || true)"
[[ -z "$PYTHON" ]] && PYTHON="/home/ut000520@uos/.pyenv/shims/python3"

mkdir -p "$LOG_DIR"
```

- [ ] **Step 2: 更新 do_start 和 do_stop**

```bash
do_stop() {
    stop_proc "tproxy"  "$TPROXY_PIDFILE"
    stop_proc "dashboard" "$DASHBOARD_PIDFILE"
}

do_start() {
    do_stop 2>/dev/null || true

    start_proc "transparent-proxy" "$TPROXY"   "$TPROXY_PIDFILE"   "$TPROXY_LOG"
    sleep 1.5
    start_proc "dashboard"         "$DASHBOARD" "$DASHBOARD_PIDFILE" "$DASHBOARD_LOG"

    echo
    echo "[start.sh] ─────────────────────────────────────"
    echo "[start.sh] Transparent proxy: 127.0.0.1:8444"
    echo "[start.sh] Dashboard:         http://127.0.0.1:9090"
    echo "[start.sh] Logs:  $TPROXY_LOG"
    echo "[start.sh]        $DASHBOARD_LOG"
    echo "[start.sh] Stop:  $0 stop"
    echo "[start.sh] ─────────────────────────────────────"
}
```

- [ ] **Step 3: 更新 do_foreground**

将 `do_foreground` 中的 `$GATEWAY` 替换为 `$TPROXY`，`$GATEWAY_PIDFILE`/`$GATEWAY_LOG` 替换为 `$TPROXY_PIDFILE`/`$TPROXY_LOG`。

- [ ] **Step 4: 更新 do_status**

```bash
do_status() {
    if is_running "$TPROXY_PIDFILE"; then
        echo "[start.sh] Transparent proxy: running (pid=$(cat "$TPROXY_PIDFILE"))"
    else
        echo "[start.sh] Transparent proxy: stopped"
    fi
    if is_running "$DASHBOARD_PIDFILE"; then
        echo "[start.sh] Dashboard: running (pid=$(cat "$DASHBOARD_PIDFILE"))"
    else
        echo "[start.sh] Dashboard: stopped"
    fi
}
```

- [ ] **Step 5: 添加 setup 子命令**

```bash
do_setup() {
    echo "[start.sh] Running one-time root setup..."
    sudo bash "$PROJECT_DIR/setup_iptables.sh"
}
```

- [ ] **Step 6: 更新 main case 分支**

```bash
case "${1:-start}" in
    start)   do_start ;;
    -d|daemon) do_start ;;
    fg|foreground) do_foreground ;;
    stop)    do_stop ;;
    restart) do_start ;;
    status)  do_status ;;
    setup)   do_setup ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|fg|setup}"
        echo
        echo "  start    Start transparent proxy + dashboard (default)"
        echo "  -d       Same as start (daemon mode)"
        echo "  fg       Start in foreground (Ctrl+C to stop both)"
        echo "  stop     Stop both"
        echo "  restart  Restart both"
        echo "  status   Show running status"
        echo "  setup    One-time root setup (iptables + cgroup + CA)"
        exit 1
        ;;
esac
```

- [ ] **Step 7: 验证语法**

```bash
bash -n start.sh
```
Expected: 无输出。

- [ ] **Step 8: 提交**

```bash
git add start.sh
git commit -m "refactor: start.sh 改为透明代理模式 + setup 子命令"
```

---

### Task 6: 清理 agentgatewayd.py gsettings 代理管理代码

**Files:**
- Modify: `gateway/agentgatewayd.py`

**Interfaces:**
- Consumes: 无
- Produces: 清理后的 agentgatewayd.py，无 gsettings 代理设置/恢复

- [ ] **Step 1: 查找 gsettings 相关代码**

```bash
cd /home/ut000520@uos/Desktop/agentos/agentgateway
grep -n "gsettings\|gw_proxy_setup\|gw_proxy_restore\|gsettings_proxy" gateway/agentgatewayd.py
```

- [ ] **Step 2: 删除 gsettings 代理设置/恢复函数**

删除 `gw_proxy_setup()`、`gw_proxy_restore()` 及相关调用。这些函数在网关启动时设置 gsettings 系统代理为 manual，停止时恢复。透明代理模式下不再需要。

同时删除启动时调用 `gw_proxy_setup()` 和 atexit/信号处理中调用 `gw_proxy_restore()` 的代码。

- [ ] **Step 3: 验证 agentgatewayd.py 仍可 import**

```bash
python3 -c "import sys; sys.path.insert(0, 'gateway'); import agentgatewayd; print('OK')"
```
Expected: `OK`

- [ ] **Step 4: 验证 transparent_proxy.py 仍可启动**

```bash
timeout 3 python3 gateway/transparent_proxy.py 2>&1
```
Expected: 正常启动监听。

- [ ] **Step 5: 提交**

```bash
git add gateway/agentgatewayd.py
git commit -m "refactor: 删除 agentgatewayd gsettings 代理管理（透明代理不需要）"
```

---

### Task 7: 更新 README.md

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: 新方案的部署步骤
- Produces: 与代码一致的 README

- [ ] **Step 1: 更新 README 方案描述**

将 README 中方案A/B并存的描述改为统一方案：
- 移除方案A（用户态验证）和方案B（BPF-LSM 6.6内核）并存的描述
- 描述新方案：iptables REDIRECT + cgroup net_cls + 透明代理 + 系统级 CA
- 更新部署步骤为 `./start.sh setup` + `./start.sh start` + `./trustexec.sh --app xxx <cmd>`
- 更新文件清单

- [ ] **Step 2: 提交**

```bash
git add README.md
git commit -m "docs: 更新 README 为统一透明代理方案"
```

---

### Task 8: 集成验证

**Files:**
- 无修改，仅验证

- [ ] **Step 1: 验证 transparent_proxy.py 启动**

```bash
cd /home/ut000520@uos/Desktop/agentos/agentgateway
timeout 3 python3 gateway/transparent_proxy.py 2>&1
```
Expected: `[TPROXY] AgentGateway transparent proxy listening on 127.0.0.1:8444`

- [ ] **Step 2: 验证 trustexec.sh 语法和帮助**

```bash
bash -n trustexec.sh
./trustexec.sh 2>&1 | head -3
```
Expected: 显示 Usage。

- [ ] **Step 3: 验证 setup_iptables.sh 语法**

```bash
bash -n setup_iptables.sh
```
Expected: 无输出。

- [ ] **Step 4: 验证 start.sh 语法和启动**

```bash
bash -n start.sh
./start.sh status
```
Expected: 显示 stopped 状态。

- [ ] **Step 5: 验证 agentgatewayd.py 可 import**

```bash
python3 -c "import sys; sys.path.insert(0, 'gateway'); import agentgatewayd; print('OK')"
```
Expected: `OK`

- [ ] **Step 6: 验证无残留引用**

```bash
grep -r "libauditshim\|_should_mitm\|gw_proxy_setup\|gw_proxy_restore" gateway/ start.sh trustexec.sh 2>/dev/null
```
Expected: 无输出（或仅在 agentgatewayd.py 内保留 `should_mitm` 定义供 CONNECT 路径，但 transparent_proxy 不调用）。
