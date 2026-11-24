#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
"""
AgentGateway — Transparent MITM proxy + AI request identifier + tool call tracker.

Architecture:
  1. Listens as HTTP CONNECT proxy on 127.0.0.1:8443
  2. Agents connect via HTTPS_PROXY=http://127.0.0.1:8443
  3. For each CONNECT, gateway dynamically generates a cert signed by AgentGateway CA
  4. Agent establishes TLS with gateway (trusting AgentGateway CA)
  5. Gateway decrypts, inspects, and either:
     - AUDITS and FORWARDS (AI model request — recorded, not blocked)
     - FORWARDS (non-AI traffic — blind tunnel)

Key design: No external dependencies. Pure Python stdlib + cryptography.
"""

import os
import sys
import ssl
import json
import time
import uuid
import socket
import select
import threading
import http.server
import socketserver
import urllib.parse
from datetime import datetime, timezone, timedelta
from http.client import HTTPSConnection
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ─── Configuration ────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
CERT_DIR = os.path.join(PROJECT_DIR, "certs")
AUDIT_DIR = os.path.join(PROJECT_DIR, "audit")
LOG_DIR = os.path.join(PROJECT_DIR, "logs")

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8443
CA_CERT_PATH = os.path.join(CERT_DIR, "ca-cert.pem")
CA_KEY_PATH = os.path.join(CERT_DIR, "ca-key.pem")

# AI model request detection patterns
AI_API_PATHS = [
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/responses",
    "/v1/messages",        # Anthropic
    "/v1/embeddings",
    "/chat/completions",
    "/api/v1/chat",
    "/api/chat",
    "/v1/models",
]

AI_AUTH_HEADERS = [
    "authorization",       # Bearer sk-...
    "x-api-key",          # Anthropic
    "anthropic-version",
    "x-goog-api-key",     # Gemini
]
# Hosts that may carry AI model API calls and should be MITM'd for inspection.
# Everything else is blind-tunneled (zero overhead — just a TCP pipe).
AI_HOST_PATTERNS = [
    "openai.com",
    "anthropic.com",
    "api.deepseek.com",
    "dashscope.aliyuncs.com",
    "moonshot.cn",
    "bigmodel.cn",
    "ai.uniontech.com",       # UOS AI API
    "uosai.uniontech.com",    # UOS AI model config
    "xiaou.uniontech.com",    # UOS AI auth/usage
    "agent-dev.uniontech.com",  # UOS AI agent dev
    "agentapi-dev.uniontech.com",
    "immersivetranslate.com",
    "copilot.tencent.com",
    "codebuddy.cn",
    "githubcopilot.com",
    "generativelanguage.googleapis.com",  # Gemini
    "aip.baidubce.com",  # ERNIE Bot
    "minimaxi.com",
    "spark-api.xf-yun.com",
]

def should_mitm(host):
    """Return True if the host may carry AI API calls (needs TLS inspection)."""
    host_lower = host.lower()
    for pattern in AI_HOST_PATTERNS:
        if host_lower == pattern or host_lower.endswith("." + pattern):
            return True
    return False

AI_BODY_SIGNALS = [
    "model", "messages", "prompt", "max_tokens", "temperature",
    "top_p", "stream", "choices", "completion",
    "usage", "prompt_tokens", "completion_tokens",
]

# ─── Audit Logging ────────────────────────────────────────────────────────────

_audit_lock = threading.Lock()
_audit_file = None

def audit_init():
    global _audit_file
    os.makedirs(AUDIT_DIR, exist_ok=True)
    path = os.path.join(AUDIT_DIR, "audit.jsonl")
    _audit_file = open(path, "a", buffering=1)  # line-buffered
    log(f"[AUDIT] Logging to {path}")

def audit_log(event):
    """Write an audit event. Thread-safe."""
    event["ts"] = datetime.now(timezone.utc).isoformat()
    event["ts_unix"] = time.time()
    line = json.dumps(event, ensure_ascii=False, default=str)
    with _audit_lock:
        if _audit_file:
            _audit_file.write(line + "\n")
    # Also print to stdout for real-time visibility
    decision = event.get("decision", "")
    summary = event.get("summary", "")
    if decision == "BLOCK":
        print(f"  🚫 BLOCK  │ {event.get('method','')} {event.get('path','')} │ {summary}")
    elif decision == "FORWARD":
        # Only print non-trivial forwards
        pass
    else:
        print(f"  📋 {decision or 'EVENT':6s} │ {summary}")

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")

# ─── Tool Call Chain Tracker ──────────────────────────────────────────────────

class ToolCallTracker:
    """Tracks the chain of tool calls within an agent session.

    Each agent process gets a session_id (from env var AGENTGATEWAY_SESSION_ID
    set by trustexec, or auto-generated). The tracker correlates:
    - File reads (from audited syscalls or network requests)
    - AI model calls (from intercepted HTTPS)
    - Tool executions (from audited execve)
    """

    def __init__(self):
        self._chains = {}  # session_id → list of chain events
        self._lock = threading.Lock()

    def add_event(self, session_id, event_type, detail):
        entry = {
            "seq": 0,
            "ts": time.time(),
            "type": event_type,
            "detail": detail,
        }
        with self._lock:
            chain = self._chains.setdefault(session_id, [])
            entry["seq"] = len(chain)
            chain.append(entry)
        return entry

    def get_chain(self, session_id):
        with self._lock:
            return list(self._chains.get(session_id, []))

    def get_all_sessions(self):
        with self._lock:
            return {sid: list(chain) for sid, chain in self._chains.items()}

    def dump_session(self, session_id):
        chain = self.get_chain(session_id)
        print(f"\n{'='*70}")
        print(f"📋 Tool Call Chain — Session: {session_id}")
        print(f"{'='*70}")
        for e in chain:
            ts_str = datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S.%f")[:-3]
            etype = e["type"]
            detail = e["detail"]
            if etype == "ai_request":
                print(f"  [{ts_str}] 🤖 AI REQUEST → {detail.get('target','')}")
                print(f"             model={detail.get('model','?')} "
                      f"prompt_len={detail.get('prompt_len',0)}")
                if detail.get("preview"):
                    print(f"             preview: {detail['preview'][:120]}")
            elif etype == "ai_blocked":
                print(f"  [{ts_str}] 🚫 AI BLOCKED → {detail.get('target','')}")
                print(f"             reason: {detail.get('reason','')}")
            elif etype == "tool_exec":
                print(f"  [{ts_str}] 🔧 TOOL EXEC → {detail.get('cmd','')}")
            elif etype == "file_access":
                print(f"  [{ts_str}] 📁 FILE ACCESS → {detail.get('path','')} "
                      f"({detail.get('op','')})")
            elif etype == "network":
                print(f"  [{ts_str}] 🌐 NETWORK → {detail.get('method','')} "
                      f"{detail.get('host','')}:{detail.get('port','')}")
            else:
                print(f"  [{ts_str}] ❓ {etype}: {detail}")
        print(f"{'='*70}\n")

tracker = ToolCallTracker()

# ─── Certificate Generation ───────────────────────────────────────────────────

_ca_key = None
_ca_cert = None
_cert_cache = {}  # hostname → (cert_path, key_path)
_cert_cache_lock = threading.Lock()
_gateway_key = None  # Reuse one key pair for all generated certs
_gateway_key_pem = None  # Pre-serialized PEM bytes (avoids re-encoding per host)

def load_ca():
    global _ca_key, _ca_cert, _gateway_key, _gateway_key_pem
    with open(CA_KEY_PATH, "rb") as f:
        _ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_PATH, "rb") as f:
        _ca_cert = x509.load_pem_x509_certificate(f.read())
    # Generate one key pair for all dynamically generated certs
    _gateway_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _gateway_key_pem = _gateway_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    log(f"[CA] Loaded CA: {_ca_cert.subject.rfc4514_string()}")

def generate_cert_for_host(hostname):
    """Generate a TLS certificate for the given hostname, signed by AgentGateway CA.

    Returns (cert_path, key_path) — file paths for ssl.SSLContext.load_cert_chain.
    Each host gets its own key file to avoid the shared-file race that caused
    'PEM lib' errors. Files are written once and cached.
    """
    with _cert_cache_lock:
        if hostname in _cert_cache:
            return _cert_cache[hostname]

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AgentGateway"),
    ])
    try:
        san = x509.SubjectAlternativeName([x509.DNSName(hostname)])
    except Exception:
        san = x509.SubjectAlternativeName([x509.DNSName("localhost")])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(_ca_cert.subject)
        .public_key(_gateway_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(hours=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=30))
        .add_extension(san, critical=False)
        .sign(_ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path = os.path.join(CERT_DIR, f"dyn-{hostname}.pem")
    key_path = os.path.join(CERT_DIR, f"dyn-{hostname}-key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(key_path, "wb") as f:
        f.write(_gateway_key_pem)

    with _cert_cache_lock:
        if hostname in _cert_cache:
            return _cert_cache[hostname]
        _cert_cache[hostname] = (cert_path, key_path)
    return _cert_cache[hostname]

# ─── Upstream Connection Pool ────────────────────────────────────────────────
# Reuse TLS connections to upstream servers to avoid repeated TLS handshakes
# (the #1 performance bottleneck: each handshake to a real server takes 1-3s).
_upstream_pool = {}  # (host, port) → list of available sockets
_upstream_pool_lock = threading.Lock()

def _get_upstream_socket(host, port):
    """Get a pooled upstream socket (TLS if port 443), or create a new one.

    Returns (sock, is_reused). If a pooled socket is dead, discards it and
    retries (either with another pooled socket or a fresh connection).
    """
    key = (host, port)
    with _upstream_pool_lock:
        pool = _upstream_pool.get(key, [])
        while pool:
            sock = pool.pop()
            # Check if socket is still alive (SSLSocket doesn't support MSG_PEEK)
            try:
                sock.settimeout(0.01)
                data = sock.recv(1)
                if not data:
                    sock.close()
                    continue
                # Unexpected data on idle connection — discard
                sock.close()
                continue
            except (BlockingIOError, socket.timeout, ssl.SSLWantReadError):
                # No data available → connection is alive
                sock.settimeout(30)
                return sock, True
            except (OSError, ssl.SSLError):
                sock.close()
                continue
    sock = socket.create_connection((host, port), timeout=30)
    if port == 443:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    sock.settimeout(30)
    return sock, False

def _return_upstream_socket(host, port, sock):
    """Return a socket to the pool for reuse."""
    key = (host, port)
    with _upstream_pool_lock:
        pool = _upstream_pool.setdefault(key, [])
        if len(pool) < 10:
            pool.append(sock)
            return
    try:
        sock.close()
    except OSError:
        pass

# ─── AI Request Detection ─────────────────────────────────────────────────────

def detect_ai_request(method, path, headers, body_bytes):
    """Detect if an HTTP request is an AI model API call.
    Returns (is_ai: bool, confidence: int, signals: list, detail: dict).
    """
    signals = []
    detail = {}
    confidence = 0

    # Signal 1: AI API path
    path_lower = path.lower()
    for ai_path in AI_API_PATHS:
        if ai_path in path_lower:
            signals.append(f"path_match:{ai_path}")
            confidence += 2
            break

    # Signal 2: AI auth headers
    for hdr_name in AI_AUTH_HEADERS:
        for k, v in headers.items():
            if k.lower() == hdr_name:
                signals.append(f"auth_header:{k}")
                confidence += 1
                if "bearer" in v.lower():
                    detail["auth_type"] = "bearer"
                break

    # Signal 3: Request body JSON structure
    body_str = ""
    if body_bytes:
        try:
            body_str = body_bytes.decode("utf-8", errors="replace")
            body_json = json.loads(body_str)
            detail["model"] = body_json.get("model", "")
            if "messages" in body_json:
                signals.append("body:messages[]")
                confidence += 2
                msgs = body_json.get("messages", [])
                detail["message_count"] = len(msgs)
                # Extract prompt preview
                if msgs:
                    last_msg = msgs[-1]
                    content = last_msg.get("content", "")
                    if isinstance(content, str):
                        detail["preview"] = content[:200]
                    elif isinstance(content, list):
                        for part in content:
                            if isinstance(part, dict) and part.get("type") == "text":
                                detail["preview"] = part.get("text", "")[:200]
                                break
                detail["prompt_len"] = len(body_str)
            if "prompt" in body_json:
                signals.append("body:prompt")
                confidence += 2
                detail["preview"] = str(body_json.get("prompt", ""))[:200]
                detail["prompt_len"] = len(body_str)
            for sig in ["max_tokens", "temperature", "top_p", "stream"]:
                if sig in body_json:
                    signals.append(f"body:{sig}")
                    confidence += 1
            if "model" in body_json:
                signals.append("body:model")
                confidence += 1
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    # Decision: 2+ signals or confidence >= 3
    is_ai = confidence >= 3 or len(signals) >= 2
    return is_ai, confidence, signals, detail
def detect_app_source(body_bytes, headers, peer_comm=None):
    """Detect the application source from request body and peer process name.

    Returns: (app_name, is_browser_auxiliary)
    - app_name: detected app name, or "Unknown" if cannot be identified
    - is_browser_auxiliary: True if this is a browser-side prediction/auto-complete request
      (not a real agent conversation), False otherwise

    Identification priority:
    1. Browser auxiliary detection from system prompt ("Next User Message Predictor")
       — these are sub-page prediction requests, not real agent conversations
    2. Peer process name (peer_comm) — the OS-level process name from /proc/<pid>/comm
       This is the primary, extensible identification method. Any new application
       is automatically identified by its process name without code changes.
    """
    # First check if this is a browser auxiliary prediction request
    is_browser_aux = False
    if body_bytes:
        try:
            body_json = json.loads(body_bytes.decode("utf-8", errors="replace"))
            messages = body_json.get("messages", [])
            if messages:
                sys_content = ""
                for m in messages:
                    if m.get("role") == "system":
                        content = m.get("content", "")
                        if isinstance(content, str):
                            sys_content = content
                        elif isinstance(content, list):
                            for part in content:
                                if isinstance(part, dict) and part.get("type") == "text":
                                    sys_content = part.get("text", "")
                                    break
                        break
                if "Next User Message Predictor" in sys_content:
                    return "Browser-Predict", True
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    # Use peer process name as the app identifier
    if peer_comm:
        return peer_comm, False

    return "Unknown", False

def detect_ai_response(body_bytes):
    """Detect if an HTTP response looks like an AI model response."""
    if not body_bytes:
        return False, {}
    try:
        body_str = body_bytes.decode("utf-8", errors="replace")
        # SSE streaming response
        if body_str.startswith("data: "):
            for line in body_str.split("\n"):
                if line.startswith("data: ") and "[DONE]" not in line:
                    chunk = json.loads(line[6:])
                    if "choices" in chunk or "delta" in chunk:
                        return True, {"response_type": "sse_stream"}
        # Regular JSON response
        body_json = json.loads(body_str)
        if "choices" in body_json or "usage" in body_json:
            return True, {
                "response_type": "json",
                "usage": body_json.get("usage", {}),
            }
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return False, {}

# ─── Peer Process Identification ─────────────────────────────────────────────

_proc_cache = {}          # port → (pid, comm, app_name, ts)
_proc_cache_lock = threading.Lock()
_proc_cache_ttl = 30.0    # seconds
# Limit concurrent /proc/*/fd scans — each scan does thousands of readlinks.
# Without a cap, a burst of CONNECTs spawns a burst of scanners that thrash
# the kernel and starve the proxy's own I/O.
_proc_scan_semaphore = threading.Semaphore(4)

# Processes that are transport/tooling, not the agent itself.
# When walking the parent chain we skip these to find the real agent process.
_TOOL_PROCESSES = frozenset({
    # HTTP clients
    "curl", "wget",
    # Language runtimes (the agent code runs *inside* these, but the agent
    # identity is the parent that launched the script, not the interpreter)
    "python", "python3", "python3.11", "python3.10", "python3.9", "python3.8",
    "node", "nodejs", "deno", "bun",
    # Shells
    "bash", "sh", "zsh", "dash", "fish", "ksh", "tcsh", "csh",
    # Coreutils wrappers that exec other commands
    "env", "nohup", "timeout", "xargs", "nice", "ionice", "stdbuf",
    "exec", "tee", "cat", "dd", "strace", "ltrace", "valgrind",
    # Process managers / supervisors
    "supervisord", "systemd", "init",
})


def _read_comm(pid):
    """Read /proc/<pid>/comm, return stripped name or None."""
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return None


def _read_ppid(pid):
    """Read PPid from /proc/<pid>/status, return int or None."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return None


def _resolve_agent_process(direct_pid):
    """Walk the parent chain from direct_pid to find the real agent process.

    Skips tool processes (curl, python3, bash, etc.) to find the first
    non-tool ancestor — that's the agent application.

    Returns (agent_pid, agent_comm) — the direct process if no non-tool
    ancestor is found.
    """
    comm = _read_comm(direct_pid)
    if comm is None:
        return direct_pid, None

    # If the direct process is not a tool, it IS the agent
    if comm not in _TOOL_PROCESSES:
        return direct_pid, comm

    # Walk up the parent chain
    pid = direct_pid
    visited = set()
    while pid and pid not in visited:
        visited.add(pid)
        ppid = _read_ppid(pid)
        if not ppid or ppid == 1:
            # Reached init — stop, use the direct process
            break
        parent_comm = _read_comm(ppid)
        if parent_comm is None:
            break
        if parent_comm not in _TOOL_PROCESSES:
            return ppid, parent_comm
        pid = ppid

    # All ancestors were tools — return the direct process
    return direct_pid, comm

def _lookup_peer_process(client_socket):
    """Identify the process on the other end of client_socket.

    Returns (pid, comm, app_name) or (None, None, None) if not found.
    Uses /proc/net/tcp to find the socket inode, then scans /proc/*/fd/
    to find which PID owns it, then reads /proc/<pid>/comm and environ.
    """
    try:
        peer_addr = client_socket.getpeername()  # (ip, port) of the remote peer
        local_addr = client_socket.getsockname()  # (ip, port) of our side
    except OSError:
        return None, None, None

    peer_ip = peer_addr[0]
    peer_port = peer_addr[1]
    local_port = local_addr[1]

    # Check cache
    now = time.time()
    with _proc_cache_lock:
        cached = _proc_cache.get(peer_port)
        if cached and (now - cached[3]) < _proc_cache_ttl:
            return cached[0], cached[1], cached[2]

    # Find socket inode from /proc/net/tcp.
    # We match on BOTH local_port (gateway's listening port, e.g. 8443)
    # AND remote port (client's ephemeral port). This distinguishes the
    # client→gateway socket from the gateway→upstream sockets.
    inode = None
    try:
        with open("/proc/net/tcp") as f:
            f.readline()  # skip header
            for line in f:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local_hex = parts[1]    # hex IP:PORT (local side = gateway)
                rem_hex = parts[2]      # hex IP:PORT (remote side = client)
                state = parts[3]        # 01 = ESTABLISHED
                if state != "01":
                    continue
                local_port_hex = local_hex.split(":")[1]
                rem_port_hex = rem_hex.split(":")[1]
                try:
                    l_port = int(local_port_hex, 16)
                    r_port = int(rem_port_hex, 16)
                except ValueError:
                    continue
                # Match: our listening port on local side, client's port on remote side
                if l_port == local_port and r_port == peer_port:
                    inode = parts[9]
                    break
    except OSError:
        return None, None, None

    if not inode:
        return None, None, None
    target_link = f"socket:[{inode}]"

    # Scan /proc/*/fd/ to find which PID owns this socket.
    # This should be the gateway's own PID — the client connects TO the gateway,
    # so the gateway holds the server-side socket. We need to find the OTHER
    # process that connects to us, which means we need to look at the
    # client-side socket, not the server-side.
    #
    # Actually: /proc/net/tcp shows the gateway's server-side socket
    # (local=8443, remote=client_port). The inode belongs to the gateway process.
    # To find the CLIENT process, we need to find the socket with
    # local=client_port, remote=8443 — that's the client's side of the connection.
    client_inode = None
    try:
        with open("/proc/net/tcp") as f:
            f.readline()  # skip header
            for line in f:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local_hex = parts[1]
                rem_hex = parts[2]
                state = parts[3]
                if state != "01":
                    continue
                local_port_hex = local_hex.split(":")[1]
                rem_port_hex = rem_hex.split(":")[1]
                try:
                    l_port = int(local_port_hex, 16)
                    r_port = int(rem_port_hex, 16)
                except ValueError:
                    continue
                # Client side: local=client_port, remote=8443
                if l_port == peer_port and r_port == local_port:
                    client_inode = parts[9]
                    break
    except OSError:
        pass

    # Use client_inode to find the client process
    search_inode = client_inode or inode
    search_link = f"socket:[{search_inode}]"

    # The /proc/*/fd readlink scan is the expensive part (thousands of
    # readlinks). Cap concurrent scans so a burst of CONNECTs can't spawn a
    # burst of scanners that starves the proxy's own I/O.
    pid = None
    with _proc_scan_semaphore:
        try:
            proc_dirs = [d for d in os.listdir("/proc") if d.isdigit()]
        except OSError:
            return None, None, None

        # Skip our own PID — we want the peer, not ourselves
        my_pid = os.getpid()
        for pid_str in proc_dirs:
            if int(pid_str) == my_pid:
                continue
            fd_dir = f"/proc/{pid_str}/fd"
            try:
                fds = os.listdir(fd_dir)
            except (OSError, PermissionError):
                continue
            for fd in fds:
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                    if link == search_link:
                        pid = int(pid_str)
                        break
                except (OSError, PermissionError):
                    continue
            if pid is not None:
                break
    if pid is None:
        return None, None, None

    # Walk parent chain to find the real agent process.
    # The direct PID may be curl/python3/bash — a tool the agent uses to
    # send the request. We walk up to find the actual agent application.
    agent_pid, agent_comm = _resolve_agent_process(pid)

    # Read AGENTGATEWAY_APP_NAME from /proc/<agent_pid>/environ (legacy)
    app_name = None
    try:
        with open(f"/proc/{agent_pid}/environ", "rb") as f:
            environ_raw = f.read()
        for entry in environ_raw.split(b"\x00"):
            if entry.startswith(b"AGENTGATEWAY_APP_NAME="):
                app_name = entry.split(b"=", 1)[1].decode("utf-8", errors="replace")
                break
    except (OSError, PermissionError):
        pass

    # Cache the result (keyed by peer_port, returns agent info)
    with _proc_cache_lock:
        _proc_cache[peer_port] = (agent_pid, agent_comm, app_name, now)

    return agent_pid, agent_comm, app_name
# ─── MITM Proxy Handler ───────────────────────────────────────────────────────

class MITMProxyHandler(http.server.BaseHTTPRequestHandler):
    """Handles CONNECT requests for HTTPS MITM and regular HTTP proxy."""

    # Suppress default logging
    def log_message(self, format, *args):
        pass

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError, OSError):
            pass

    def do_CONNECT(self):
        """Handle HTTPS CONNECT.

        Only hosts that may carry AI API calls are MITM'd (for request
        inspection). All other HTTPS traffic is blind-tunneled with zero
        overhead — just a bidirectional TCP pipe, no double TLS, no
        response buffering.
        """
        host, port = self.path.split(":")
        port = int(port)
        session_id = getattr(self, "_session_id", "unknown")

        # Track network event
        tracker.add_event(session_id, "network", {
            "method": "CONNECT",
            "host": host,
            "port": port,
        })

        if should_mitm(host):
            # Capture the raw TCP socket NOW — _do_mitm_connect will reassign
            # self.connection to a TLS-wrapped socket, and the lookup must
            # read /proc/net/tcp against the original connection.
            # Start peer lookup AFTER sending the 200 response to avoid
            # GIL contention from /proc/*/fd readlink scanning stalling
            # the response.
            self._send_connect_ok()
            self._start_peer_lookup(self.connection)
            self._do_mitm_connect_after_ok(host, port, session_id)
        else:
            self._do_blind_tunnel(host, port, session_id)

    def _start_peer_lookup(self, client_socket=None):
        """Launch the background peer-process lookup (non-blocking).

        _lookup_peer_process scans /proc/*/fd/* (thousands of readlinks); doing
        it synchronously on the request path stalls every proxied request. We
        run it in a daemon thread and store the result on self._peer_*; callers
        that need peer info call _join_peer_lookup() first.

        client_socket: the raw TCP socket to identify. Must be captured before
        any TLS wrapping (self.connection gets reassigned in the MITM path).
        """
        # Avoid double-starting if a handler is reused across requests.
        if getattr(self, "_peer_lookup", None) is not None:
            return
        sock = client_socket if client_socket is not None else self.connection
        self._peer_lookup = threading.Thread(
            target=self._run_peer_lookup, args=(sock,),
            name="agw-peer-lookup", daemon=True
        )
        self._peer_lookup.start()

    def _run_peer_lookup(self, client_socket):
        """Background worker: resolve peer process info into self._peer_*."""
        try:
            peer_pid, peer_comm, peer_app_name = _lookup_peer_process(client_socket)
        except Exception:
            peer_pid, peer_comm, peer_app_name = None, None, None
        self._peer_pid = peer_pid
        self._peer_comm = peer_comm
        self._peer_app_name = peer_app_name
        session_id = getattr(self, "_session_id", "unknown")
        host_port = getattr(self, "path", "?")
        if peer_comm:
            log(f"[CONNECT] {host_port} (session={session_id}) from pid={peer_pid} comm={peer_comm} app={peer_app_name or '(none)'}")
        else:
            log(f"[CONNECT] {host_port} (session={session_id}) from pid=unknown")

    def _join_peer_lookup(self, timeout=0.0):
        """Wait briefly for the background peer lookup, if still running."""
        t = getattr(self, "_peer_lookup", None)
        if t is not None and t.is_alive():
            t.join(timeout)

    def _do_blind_tunnel(self, host, port, session_id, already_handshaked=False):
        """Blind TCP tunnel — no TLS interception, just pipe bytes."""
        if not already_handshaked:
            # Send 200 Connection Established
            self.send_response(200, "Connection Established")
            self.end_headers()

        # Connect to real server
        try:
            remote = socket.create_connection((host, port), timeout=30)
        except Exception as e:
            log(f"[TUNNEL] Failed to connect to {host}:{port}: {e}")
            return

        client = self.connection
        try:
            # Use poll() instead of select() — select() fails with
            # "filedescriptor out of range" when FD numbers exceed 1024
            # (common in long-running processes with many connections).
            poller = select.poll()
            poller.register(client, select.POLLIN | select.POLLERR | select.POLLHUP)
            poller.register(remote, select.POLLIN | select.POLLERR | select.POLLHUP)
            fd_to_sock = {client.fileno(): client, remote.fileno(): remote}
            while True:
                events = poller.poll(60000)  # 60s timeout
                if not events:
                    break  # timeout
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

    def _send_connect_ok(self):
        """Send 200 Connection Established immediately."""
        self.send_response(200, "Connection Established")
        self.end_headers()

    def _do_mitm_connect_after_ok(self, host, port, session_id):
        """Establish MITM TLS after 200 has been sent; fall back to tunnel."""
        # Generate cert for this host and wrap in TLS
        cert_path, key_path = generate_cert_for_host(host)

        # Wrap client socket in TLS (we are the "server")
        try:
            client_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            client_ssl.load_cert_chain(certfile=cert_path, keyfile=key_path)
            tls_socket = client_ssl.wrap_socket(
                self.connection, server_side=True,
            )
        except (ssl.SSLError, OSError) as e:
            # Client rejected our CA (cert pinning, untrusted CA, etc.).
            # Fall back to blind tunnel so traffic still flows.
            log(f"[TLS] MITM failed for {host}, falling back to tunnel: {e}")
            self._do_blind_tunnel(host, port, session_id, already_handshaked=True)
            return

        # Now we have a TLS tunnel. Read HTTP requests from inside the tunnel.
        self._handle_tls_tunnel(tls_socket, host, port, session_id)

    def _handle_tls_tunnel(self, tls_socket, host, port, session_id):
        """Read HTTP requests from inside the MITM TLS tunnel."""
        # Save original socket, swap to TLS socket
        original_socket = self.connection
        original_rfile = self.rfile
        self.connection = tls_socket
        self.rfile = tls_socket.makefile("rb", buffering=8192)

        try:
            # Handle multiple requests on the same connection (keep-alive)
            while True:
                try:
                    self.do_TUNNELED(host, port, session_id)
                except (ssl.SSLError, ConnectionResetError, BrokenPipeError,
                        OSError, http.server.socket.timeout):
                    break
        finally:
            try:
                tls_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                tls_socket.close()
            except OSError:
                pass
            self.connection = original_socket
            self.rfile = original_rfile

    def do_TUNNELED(self, host, port, session_id):
        """Handle a single HTTP request inside the TLS tunnel."""
        # Read the request line
        request_line = self.rfile.readline(8192)
        if not request_line or request_line == b"\r\n":
            return

        try:
            method, path, version = request_line.decode("utf-8", errors="replace").strip().split(" ", 2)
        except ValueError:
            return

        # Read headers
        headers = {}
        raw_headers = []
        while True:
            line = self.rfile.readline(8192)
            if not line or line.strip() == b"":
                break
            try:
                key, val = line.decode("utf-8", errors="replace").strip().split(":", 1)
                headers[key.strip()] = val.strip()
                raw_headers.append((key.strip(), val.strip()))
            except ValueError:
                continue

        # Read body
        body_bytes = b""
        cl = headers.get("Content-Length") or headers.get("content-length")
        if cl:
            try:
                body_len = int(cl)
                body_bytes = self.rfile.read(body_len)
            except (ValueError, OSError):
                pass
        elif headers.get("Transfer-Encoding", "").lower() == "chunked":
            # Read chunked body
            body_bytes = self._read_chunked()

        # ── AI Request Detection ──
        is_ai, confidence, signals, detail = detect_ai_request(
            method, path, headers, body_bytes
        )

        target = f"{host}:{port}"
        # ── App Source Detection ──
        # Identify the application by the peer process name from /proc/<pid>/comm.
        # This is automatic and extensible — no keyword matching needed.
        # Browser auxiliary prediction requests are still detected from the
        # request body's system prompt and separated into their own session.
        # The peer-process lookup ran in a background thread (see do_CONNECT);
        # by now the TLS handshake + request read has consumed enough time
        # that it is almost certainly done. Wait a little longer so peer_comm
        # is available for app-source detection, then fall back gracefully.
        self._join_peer_lookup(timeout=0.1)
        peer_pid = getattr(self, "_peer_pid", None)
        peer_comm = getattr(self, "_peer_comm", None)
        peer_app_name = getattr(self, "_peer_app_name", None)

        # Prefer AGENTGATEWAY_APP_NAME (set by trustexec.sh) over the raw
        # process name — e.g. "uos-ai" instead of "uos-ai-assistan" (truncated).
        effective_app, is_browser_aux = detect_app_source(body_bytes, headers, peer_comm)
        if peer_app_name and not is_browser_aux:
            effective_app = peer_app_name

        # Browser auxiliary requests (predictions) get a separate session
        effective_session = session_id
        effective_agent = getattr(self, "_agent_id", "unknown")
        if is_browser_aux:
            effective_session = f"{session_id}-browser"
            effective_agent = f"{effective_agent}-browser"

        if is_ai:
            # AUDIT the AI request, then forward it (don't block — agent must function)
            model = detail.get("model", "unknown")
            preview = detail.get("preview", "")
            prompt_len = detail.get("prompt_len", 0)

            log(f"  🔍 AI DETECTED → {method} {target}{path}")
            log(f"     model={model} confidence={confidence} signals={signals}")
            if preview:
                log(f"     preview: {preview[:100]}")

            # Track in tool call chain
            tracker.add_event(effective_session, "ai_request", {
                "target": target,
                "path": path,
                "method": method,
                "model": model,
                "prompt_len": prompt_len,
                "preview": preview,
                "confidence": confidence,
                "signals": signals,
            })
            tracker.add_event(effective_session, "ai_audited", {
                "target": target,
                "path": path,
                "model": model,
                "reason": "AI request audited and forwarded by AgentGateway policy",
            })

            # Generate request ID for traceability
            request_id = f"req-{uuid.uuid4().hex[:12]}"

            # Capture full request details for dashboard
            req_headers_sanitized = {}
            for k, v in headers.items():
                if k.lower() in ("authorization", "x-api-key", "cookie", "set-cookie"):
                    req_headers_sanitized[k] = v[:20] + "***REDACTED***"
                else:
                    req_headers_sanitized[k] = v
            try:
                req_body_json = json.loads(body_bytes.decode("utf-8", errors="replace"))
            except Exception:
                req_body_json = None
            stream_mode = False
            if isinstance(req_body_json, dict):
                stream_mode = bool(req_body_json.get("stream", False))

            # Audit log (record as AUDIT, not BLOCK — we forward it)
            audit_log({
                "agent_id": effective_agent,
                "app_name": effective_app,
                "peer_pid": peer_pid,
                "peer_comm": peer_comm,
                "session_id": effective_session,
                "request_id": request_id,
                "event": "ai_request_audited",
                "method": method,
                "host": host,
                "port": port,
                "path": path,
                "model": model,
                "confidence": confidence,
                "signals": signals,
                "prompt_len": prompt_len,
                "preview": preview[:500],
                "request_headers": req_headers_sanitized,
                "request_body": req_body_json,
                "request_body_raw": body_bytes.decode("utf-8", errors="replace")[:10000],
                "stream_mode": stream_mode,
                "decision": "AUDIT",
                "summary": f"AI request audited & forwarded: {method} {host}{path} model={model}",
            })

            # Forward the AI request to the real server (don't block!)
            import time as _time
            _t0 = _time.time()
            try:
                resp_status, resp_headers, resp_body = self._forward_request(
                    host, port, method, path, headers, body_bytes
                )
                _latency_ms = int((_time.time() - _t0) * 1000)

                # Check if response looks like AI
                is_ai_resp, resp_detail = detect_ai_response(resp_body)
                if is_ai_resp:
                    tracker.add_event(effective_session, "ai_response_detected", {
                        "target": target,
                        "path": path,
                        "response_detail": resp_detail,
                    })

                # Capture response details for dashboard
                resp_headers_dict = {}
                for k, v in resp_headers:
                    if k.lower() in ("authorization", "x-api-key", "cookie", "set-cookie"):
                        resp_headers_dict[k] = v[:20] + "***REDACTED***"
                    else:
                        resp_headers_dict[k] = v
                try:
                    resp_body_json = json.loads(resp_body.decode("utf-8", errors="replace"))
                except Exception:
                    resp_body_json = None
                # Extract token usage from response
                token_usage = {}
                if stream_mode and resp_body:
                    # For SSE streaming responses, parse the last data: chunk for usage
                    raw_text = resp_body.decode("utf-8", errors="replace")
                    for sse_line in reversed(raw_text.split("\n")):
                        sse_line = sse_line.strip()
                        if sse_line.startswith("data:") and sse_line != "data: [DONE]":
                            try:
                                chunk = json.loads(sse_line[5:].strip())
                                usage = chunk.get("usage", {})
                                if usage:
                                    token_usage = {
                                        "prompt_tokens": usage.get("prompt_tokens", 0),
                                        "completion_tokens": usage.get("completion_tokens", 0),
                                        "total_tokens": usage.get("total_tokens", 0),
                                    }
                                    cached = usage.get("prompt_tokens_details", {})
                                    if isinstance(cached, dict):
                                        token_usage["cached_tokens"] = cached.get("cached_tokens", 0)
                                    break
                            except Exception:
                                continue
                elif resp_body_json and isinstance(resp_body_json, dict):
                    usage = resp_body_json.get("usage", {})
                    if usage:
                        token_usage = {
                            "prompt_tokens": usage.get("prompt_tokens", 0),
                            "completion_tokens": usage.get("completion_tokens", 0),
                            "total_tokens": usage.get("total_tokens", 0),
                        }
                        cached = usage.get("prompt_tokens_details", {})
                        if isinstance(cached, dict):
                            token_usage["cached_tokens"] = cached.get("cached_tokens", 0)
                audit_log({
                    "agent_id": effective_agent,
                    "app_name": effective_app,
                    "peer_pid": peer_pid,
                    "peer_comm": peer_comm,
                    "session_id": effective_session,
                    "request_id": request_id,
                    "event": "ai_response",
                    "method": method,
                    "host": host,
                    "path": path,
                    "model": model,
                    "response_status": resp_status,
                    "response_headers": resp_headers_dict,
                    "response_body": resp_body_json,
                    "response_body_raw": resp_body.decode("utf-8", errors="replace")[:10000],
                    "token_usage": token_usage,
                    "latency_ms": _latency_ms,
                    "stream_mode": stream_mode,
                    "decision": "AUDIT",
                    "summary": f"AI response {resp_status} from {host}{path} model={model} latency={_latency_ms}ms tokens={token_usage.get('total_tokens',0)}",
                })

                # Send response back to client
                resp_line = f"HTTP/1.1 {resp_status} {http.server.BaseHTTPRequestHandler.responses.get(resp_status, ('OK',))[0]}\r\n"
                self.connection.sendall(resp_line.encode("utf-8"))
                for k, v in resp_headers:
                    if k.lower() not in ("transfer-encoding", "connection"):
                        self.connection.sendall(f"{k}: {v}\r\n".encode("utf-8"))
                self.connection.sendall(f"Content-Length: {len(resp_body)}\r\n".encode("utf-8"))
                self.connection.sendall(b"X-AgentGateway-Decision: AUDIT\r\n")
                self.connection.sendall(b"X-AgentGateway-Confidence: " + str(confidence).encode() + b"\r\n")
                self.connection.sendall(b"X-AgentGateway-Request-Id: " + request_id.encode() + b"\r\n")
                self.connection.sendall(b"Connection: close\r\n\r\n")
                self.connection.sendall(resp_body)
            except Exception as e:
                log(f"  ⚠️ AI forward error: {e}")
                audit_log({
                    "agent_id": effective_agent,
                    "app_name": effective_app,
                    "peer_pid": peer_pid,
                    "peer_comm": peer_comm,
                    "session_id": effective_session,
                    "request_id": request_id,
                    "event": "ai_forward_error",
                    "method": method,
                    "host": host,
                    "path": path,
                    "model": model,
                    "error": str(e),
                    "decision": "AUDIT",
                    "summary": f"AI forward error: {e}",
                })
                error_body = json.dumps({
                    "error": {
                        "type": "agentgateway_forward_error",
                        "message": str(e),
                    }
                }, ensure_ascii=False).encode("utf-8")
                resp = (
                    f"HTTP/1.1 502 Bad Gateway\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(error_body)}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode("utf-8")
                self.connection.sendall(resp)
                self.connection.sendall(error_body)
            return

        # ── Non-AI: Forward the request ──
        audit_log({
            "agent_id": effective_agent,
            "app_name": effective_app,
            "peer_pid": peer_pid,
            "peer_comm": peer_comm,
            "session_id": effective_session,
            "event": "http_forward",
            "method": method,
            "host": host,
            "port": port,
            "path": path,
            "decision": "FORWARD",
            "summary": f"{method} {host}:{port}{path}",
        })

        # Forward to real server
        try:
            resp_status, resp_headers, resp_body = self._forward_request(
                host, port, method, path, headers, body_bytes
            )

            # Check if response looks like AI
            is_ai_resp, resp_detail = detect_ai_response(resp_body)
            if is_ai_resp:
                tracker.add_event(session_id, "ai_response_detected", {
                    "target": target,
                    "path": path,
                    "response_detail": resp_detail,
                })
                audit_log({
                    "agent_id": effective_agent,
                    "app_name": effective_app,
                    "session_id": effective_session,
                    "event": "ai_response_detected",
                    "host": host,
                    "path": path,
                    "response_detail": resp_detail,
                    "decision": "AUDIT",
                    "summary": f"AI response detected from {host}{path}",
                })

            # Send response back to client
            resp_line = f"HTTP/1.1 {resp_status} {http.server.BaseHTTPRequestHandler.responses.get(resp_status, ('OK',))[0]}\r\n"
            self.connection.sendall(resp_line.encode("utf-8"))
            for k, v in resp_headers:
                if k.lower() not in ("transfer-encoding", "connection"):
                    self.connection.sendall(f"{k}: {v}\r\n".encode("utf-8"))
            self.connection.sendall(f"Content-Length: {len(resp_body)}\r\n".encode("utf-8"))
            self.connection.sendall(b"Connection: close\r\n\r\n")
            self.connection.sendall(resp_body)

        except Exception as e:
            error_body = json.dumps({
                "error": {
                    "type": "agentgateway_forward_error",
                    "message": str(e),
                }
            }).encode("utf-8")
            resp = (
                f"HTTP/1.1 502 Bad Gateway\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(error_body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode("utf-8")
            self.connection.sendall(resp)
            self.connection.sendall(error_body)

    def _forward_request(self, host, port, method, path, headers, body):
        """Forward request to real destination and return response."""
        # Retry once: a pooled socket may be dead (server closed it after
        # the keep-alive timeout), in which case recv returns empty and we
        # need a fresh connection.
        for _attempt in range(2):
            sock, is_reused = _get_upstream_socket(host, port)
            try:
                return self._do_forward(host, port, sock, method, path, headers, body)
            except (socket.timeout, ConnectionError, ssl.SSLError, OSError) as e:
                try:
                    sock.close()
                except OSError:
                    pass
                if not is_reused:
                    raise
                log(f"[POOL] Retrying {host}:{port} with fresh connection after: {e}")
        return 502, [], b"Bad Gateway"

    def _do_forward(self, host, port, sock, method, path, headers, body):
        """Send request on sock, read response, return socket to pool."""
        # Build raw request — use keep-alive so we can return socket to pool
        req_line = f"{method} {path} HTTP/1.1\r\n"
        req = req_line.encode("utf-8")
        for k, v in headers.items():
            if k.lower() in ("proxy-connection", "proxy-authorization", "connection"):
                continue
            req += f"{k}: {v}\r\n".encode("utf-8")
        req += b"Connection: keep-alive\r\n\r\n"
        req += body

        sock.sendall(req)

        # Read response — read headers first, then body by Content-Length or chunked
        resp_buf = b""
        while b"\r\n\r\n" not in resp_buf:
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("upstream closed connection before headers")
            resp_buf += chunk

        header_end = resp_buf.find(b"\r\n\r\n")
        if header_end == -1:
            _return_upstream_socket(host, port, sock)
            return 502, [], b"Bad Gateway"

        header_block = resp_buf[:header_end].decode("utf-8", errors="replace")
        body_data = resp_buf[header_end + 4:]

        lines = header_block.split("\r\n")
        status_line = lines[0]
        try:
            _, status_code, _ = status_line.split(" ", 2)
            status_code = int(status_code)
        except ValueError:
            status_code = 502

        resp_headers = []
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                resp_headers.append((k.strip(), v.strip()))

        # Determine body length to know when we've read the full response
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

        # Read remaining body
        if is_chunked:
            # Read until chunked terminator 0\r\n\r\n appears at end.
            # Using endswith on the accumulated buffer avoids O(n²) scanning
            # and correctly handles the terminator spanning recv boundaries.
            terminator = b"0\r\n\r\n"
            while not body_data.endswith(terminator):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                body_data += chunk
            body_data = self._dechunk(body_data)
        elif content_length is not None:
            while len(body_data) < content_length:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                body_data += chunk
        else:
            # No content-length, no chunked — read until connection closes
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                body_data += chunk
            connection_close = True

        # Return socket to pool if server supports keep-alive
        if connection_close:
            try:
                sock.close()
            except OSError:
                pass
        else:
            _return_upstream_socket(host, port, sock)

        return status_code, resp_headers, body_data

    def _read_chunked(self):
        """Read chunked transfer-encoded body."""
        body = b""
        while True:
            line = self.rfile.readline(8192)
            if not line:
                break
            try:
                chunk_size = int(line.strip(), 16)
            except ValueError:
                break
            if chunk_size == 0:
                self.rfile.readline()  # Read trailing CRLF
                break
            chunk = self.rfile.read(chunk_size)
            body += chunk
            self.rfile.readline()  # Read trailing CRLF
        return body

    def _dechunk(self, data):
        """Dechunk HTTP chunked response body."""
        result = b""
        pos = 0
        while pos < len(data):
            crlf = data.find(b"\r\n", pos)
            if crlf == -1:
                break
            try:
                chunk_size = int(data[pos:crlf].strip(), 16)
            except ValueError:
                break
            if chunk_size == 0:
                break
            result += data[crlf + 2 : crlf + 2 + chunk_size]
            pos = crlf + 2 + chunk_size + 2
        return result

    def do_GET(self):
        """Handle direct HTTP GET (non-CONNECT, for HTTP proxy)."""
        session_id = getattr(self, "_session_id", "unknown")
        self._start_peer_lookup()
        # Parse the URL
        parsed = urllib.parse.urlparse(self.path)
        host = parsed.hostname
        port = parsed.port or 80
        path = parsed.path
        if parsed.query:
            path += "?" + parsed.query

        is_ai, confidence, signals, detail = detect_ai_request(
            "GET", path, dict(self.headers), b""
        )
        if is_ai:
            self._audit_and_forward("GET", host, port, path, dict(self.headers), b"", confidence, signals, detail, session_id)
        else:
            self._forward_http("GET", host, port, path, dict(self.headers), b"", session_id)

    def do_POST(self):
        """Handle direct HTTP POST."""
        session_id = getattr(self, "_session_id", "unknown")
        self._start_peer_lookup()
        parsed = urllib.parse.urlparse(self.path)
        host = parsed.hostname
        port = parsed.port or 80
        path = parsed.path
        if parsed.query:
            path += "?" + parsed.query

        body = b""
        cl = self.headers.get("Content-Length")
        if cl:
            body = self.rfile.read(int(cl))

        is_ai, confidence, signals, detail = detect_ai_request(
            "POST", path, dict(self.headers), body
        )
        if is_ai:
            self._audit_and_forward("POST", host, port, path, dict(self.headers), body, confidence, signals, detail, session_id)
        else:
            self._forward_http("POST", host, port, path, dict(self.headers), body, session_id)

    def _audit_and_forward(self, method, host, port, path, headers, body, confidence, signals, detail, session_id):
        """Audit AI request and forward it (don't block — agent must function)."""
        model = detail.get("model", "unknown")
        preview = detail.get("preview", "")
        prompt_len = detail.get("prompt_len", 0)

        # Detect app source from peer process name. The peer-process lookup
        # ran in a background thread (see _start_peer_lookup); wait briefly so
        # peer_comm is available, then fall back gracefully.
        self._join_peer_lookup(timeout=3.0)
        peer_comm = getattr(self, "_peer_comm", None)
        effective_app, is_browser_aux = detect_app_source(body, headers, peer_comm)
        effective_session = session_id
        effective_agent = getattr(self, "_agent_id", "unknown")
        if is_browser_aux:
            effective_session = f"{session_id}-browser"
            effective_agent = f"{effective_agent}-browser"

        log(f"  🔍 AI DETECTED → {method} {host}:{port}{path}")
        log(f"     model={model} confidence={confidence} signals={signals}")

        tracker.add_event(effective_session, "ai_request", {
            "target": f"{host}:{port}",
            "path": path,
            "method": method,
            "model": model,
            "prompt_len": prompt_len,
            "preview": preview,
            "confidence": confidence,
            "signals": signals,
        })
        audit_log({
            "agent_id": effective_agent,
            "app_name": effective_app,
            "session_id": effective_session,
            "event": "ai_request_audited",
            "method": method,
            "host": host,
            "port": port,
            "path": path,
            "model": model,
            "confidence": confidence,
            "signals": signals,
            "prompt_len": prompt_len,
            "preview": preview[:500],
            "decision": "AUDIT",
            "summary": f"AI request audited & forwarded: {method} {host}:{port}{path} model={model}",
        })

        # Forward to real server
        try:
            status, resp_headers, resp_body = self._forward_request(
                host, port, method, path, headers, body
            )
            self.send_response(status)
            for k, v in resp_headers:
                if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                    self.send_header(k, v)
            self.send_header("Content-Length", len(resp_body))
            self.send_header("X-AgentGateway-Decision", "AUDIT")
            self.send_header("X-AgentGateway-Confidence", str(confidence))
            self.end_headers()
            self.wfile.write(resp_body)
        except Exception as e:
            log(f"  ⚠️ AI forward error: {e}")
            self.send_error(502, str(e))

    def _forward_http(self, method, host, port, path, headers, body, session_id):
        """Forward HTTP request (non-TLS)."""
        try:
            status, resp_headers, resp_body = self._forward_request(
                host, port, method, path, headers, body
            )
            self.send_response(status)
            for k, v in resp_headers:
                if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                    self.send_header(k, v)
            self.send_header("Content-Length", len(resp_body))
            self.end_headers()
            self.wfile.write(resp_body)
            audit_log({
                "agent_id": getattr(self, "_agent_id", "unknown"),
                "app_name": getattr(self, "_app_name", "unknown"),
                "session_id": session_id,
                "event": "http_forward",
                "method": method,
                "host": host,
                "port": port,
                "path": path,
                "decision": "FORWARD",
                "summary": f"{method} {host}:{port}{path}",
            })
        except Exception as e:
            self.send_error(502, str(e))


class ThreadingHTTPProxyServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_request_noblock(self):
        """Override to inject session context from client socket."""
        try:
            request, client_address = self.get_request()
        except OSError:
            return
        # Extract session info from client connection
        # Session ID can be passed via:
        # 1. HTTP header X-AgentGateway-Session
        # 2. TLS SNI
        # 3. Process info (pid → cgroup → agent_id)
        # For now, we auto-generate per-connection and can be overridden by header
        if self.verify_request(request, client_address):
            try:
                self.process_request(request, client_address)
            except Exception:
                self.handle_error(request, client_address)
                self.shutdown_request(request)


def make_handler_with_session(agent_id, session_id, app_name="unknown"):
    """Create a handler class with injected session context."""
    class SessionInjectedHandler(MITMProxyHandler):
        _agent_id = agent_id
        _session_id = session_id
        _app_name = app_name
    return SessionInjectedHandler


def main():
    os.makedirs(AUDIT_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(CERT_DIR, exist_ok=True)

    audit_init()
    load_ca()
    # Default session for standalone testing
    agent_id = os.environ.get("AGENTGATEWAY_AGENT_ID", f"agent-{uuid.uuid4().hex[:8]}")
    session_id = os.environ.get("AGENTGATEWAY_SESSION_ID", f"session-{uuid.uuid4().hex[:8]}")
    app_name = os.environ.get("AGENTGATEWAY_APP_NAME", "unknown")

    handler = make_handler_with_session(agent_id, session_id, app_name)
    server = ThreadingHTTPProxyServer((GATEWAY_HOST, GATEWAY_PORT), handler)

    log(f"{'='*60}")
    log(f"AgentGateway started (CONNECT proxy — fallback path)")
    log(f"  Proxy:    {GATEWAY_HOST}:{GATEWAY_PORT}")
    log(f"  Agent:    {agent_id}")
    log(f"  App:      {app_name}")
    log(f"  Session:  {session_id}")
    log(f"  CA cert:  {CA_CERT_PATH}")
    log(f"  Audit:    {os.path.join(AUDIT_DIR, 'audit.jsonl')}")
    log(f"{'='*60}")
    log(f"Primary interception: transparent_proxy.py :8444 (iptables REDIRECT)")
    log(f"This CONNECT proxy is a fallback for explicit proxy clients.")
    log(f"{'='*60}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("\n[SHUTDOWN] Dumping tool call chains...")
        for sid in tracker.get_all_sessions():
            tracker.dump_session(sid)
        log("[SHUTDOWN] Done.")
        server.shutdown()

if __name__ == "__main__":
    main()
