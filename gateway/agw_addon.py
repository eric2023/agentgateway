#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
#
# AgentGateway mitmproxy addon — AI request audit + process attribution.
#
# Loaded by mitmdump in transparent mode:
#   mitmdump --mode transparent --listen-host 127.0.0.1 --listen-port 8444 \
#     --set ssl_insecure=true -s gateway/agw_addon.py
#
# Reuses agentgatewayd.py for:
#   - detect_ai_request(): L7 AI request identification
#   - audit_log() / audit_init(): JSONL audit logging
#   - _resolve_agent_process(): parent-chain walk to find real agent
#   - _proc_cache / _proc_scan_semaphore: process lookup caching/throttling

import json
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agentgatewayd as gw

# mitmproxy 5.x uses pyOpenSSL; import after agentgatewayd so sys.path is set.
from mitmproxy import http

LISTEN_PORT = 8444

_REDACT_HEADERS = frozenset(
    ("authorization", "x-api-key", "cookie", "x-goog-api-key")
)


def _redact_headers(headers):
    out = {}
    for k, v in headers.items():
        if k.lower() in _REDACT_HEADERS:
            out[k] = (v[:20] + "***REDACTED***") if v else v
        else:
            out[k] = v
    return out
def _find_socket_inode(peer_port, exclude_port):
    """Find socket inode by local port, scanning both /proc/net/tcp and tcp6."""
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

class AgentGatewayAddon:
    """mitmproxy addon: audit AI requests with process attribution."""

    def __init__(self):
        gw.audit_init()
        self.agent_id = os.environ.get(
            "AGENTGATEWAY_AGENT_ID", f"agent-{uuid.uuid4().hex[:8]}"
        )
        self.session_id = os.environ.get(
            "AGENTGATEWAY_SESSION_ID", f"session-{uuid.uuid4().hex[:8]}"
        )
        self.request_id_prefix = f"req-{uuid.uuid4().hex[:8]}"
        gw.log(
            f"[ADDON] AgentGateway addon loaded (agent={self.agent_id} "
            f"session={self.session_id})"
        )

    # ── mitmproxy hooks ────────────────────────────────────────────────

    def request(self, flow: http.HTTPFlow):
        """Identify AI requests and write audit events."""
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

        t0 = time.time()
        request_id = f"{self.request_id_prefix}-{uuid.uuid4().hex[:6]}"

        try:
            peer_pid, peer_comm, peer_app, peer_agent, peer_session = (
                self._lookup_peer(flow)
            )
        except Exception:
            peer_pid, peer_comm, peer_app, peer_agent, peer_session = (
                None, None, None, None, None,
            )

        audit_app = peer_app or peer_comm or "transparent"
        audit_agent = peer_agent or self.agent_id
        audit_session = peer_session or self.session_id

        body_str = body.decode("utf-8", errors="replace")
        try:
            request_body = json.loads(body_str)
        except (json.JSONDecodeError, ValueError):
            request_body = None
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
            "request_body": request_body,
            "stream_mode": "stream" in body_str.lower(),
            "source": "mitmproxy_addon",
            "summary": (
                f"AI request audited & forwarded: {method} {host}{path} "
                f"model={detail.get('model', '')}"
            ),
        }
        gw.audit_log(event)

        # Store for response() hook to correlate request ↔ response
        flow.metadata["agw_request_id"] = request_id
        flow.metadata["agw_request_ts"] = t0

    def response(self, flow: http.HTTPFlow):
        """Record response metadata: status, headers, body, token usage, latency."""
        request_id = flow.metadata.get("agw_request_id")
        if not request_id:
            return  # not an AI request (request() hook didn't fire)

        response = flow.response
        if not response:
            return

        t0 = flow.metadata.get("agw_request_ts")
        latency_ms = int((time.time() - t0) * 1000) if t0 else None

        resp_body = response.get_content() or b""
        resp_str = resp_body.decode("utf-8", errors="replace")
        try:
            resp_json = json.loads(resp_str)
        except (json.JSONDecodeError, ValueError):
            resp_json = None

        # Extract token usage from response body
        token_usage = {}
        if resp_json and isinstance(resp_json, dict):
            usage = resp_json.get("usage", {})
            if usage:
                token_usage = {
                    "prompt_tokens": usage.get("prompt_tokens", 0),
                    "completion_tokens": usage.get("completion_tokens", 0),
                    "total_tokens": usage.get("total_tokens", 0),
                }

        event = {
            "event": "ai_response",
            "request_id": request_id,
            "response_status": response.status_code,
            "response_headers": _redact_headers(dict(response.headers)),
            "response_body": resp_json,
            "response_body_raw": resp_str[:4000],
            "token_usage": token_usage,
            "latency_ms": latency_ms,
            "source": "mitmproxy_addon",
            "summary": (
                f"Response {response.status_code} ({latency_ms}ms)"
                if latency_ms
                else f"Response {response.status_code}"
            ),
        }
        gw.audit_log(event)

    # ── process attribution ────────────────────────────────────────────

    def _lookup_peer(self, flow):
        """Identify the agent process behind a REDIRECTed connection.

        mitmproxy transparent mode: the client's original destination was
        :443/:8443/:9443 — the kernel redirected to :8444.  In /proc/net/tcp
        the client-side socket shows local=client:peer_port,
        remote=<orig_dst>:<port>.

        Returns (pid, comm, app_name, agent_id, session_id) or all-None.
        """
        client = flow.client_conn
        peer_port = client.address[1]

        now = time.time()
        with gw._proc_cache_lock:
            cached = gw._proc_cache.get(peer_port)
            if cached and (now - cached[5]) < gw._proc_cache_ttl:
                return cached[0], cached[1], cached[2], cached[3], cached[4]

        # Match client-side socket in /proc/net/tcp and /proc/net/tcp6 by
        # local port.  Exclude the proxy's own listening port.
        client_inode = _find_socket_inode(peer_port, LISTEN_PORT)
        if not client_inode:
            return None, None, None, None, None

        search_link = f"socket:[{client_inode}]"
        pid = None
        with gw._proc_scan_semaphore:
            my_pid = os.getpid()
            try:
                proc_dirs = [d for d in os.listdir("/proc") if d.isdigit()]
            except OSError:
                return None, None, None, None, None

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
                        if os.readlink(f"{fd_dir}/{fd}") == search_link:
                            pid = int(pid_str)
                            break
                    except (OSError, PermissionError):
                        continue
                if pid is not None:
                    break

        if pid is None:
            return None, None, None, None, None

        agent_pid, agent_comm = gw._resolve_agent_process(pid)

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
        except (OSError, PermissionError):
            pass

        # Fall back to executable basename if AGENTGATEWAY_APP_NAME not set
        if not app_name and agent_pid:
            try:
                exe_path = os.readlink(f"/proc/{agent_pid}/exe")
                app_name = os.path.basename(exe_path)
            except (OSError, PermissionError):
                app_name = agent_comm

        # Generate stable agent_id/session_id from app_name if env not set
        stable_name = app_name or agent_comm or "unknown"
        if not agent_id:
            agent_id = f"agent-{stable_name}"
        if not session_id:
            session_id = f"session-{stable_name}"
        with gw._proc_cache_lock:
            gw._proc_cache[peer_port] = (
                agent_pid, agent_comm, app_name, agent_id, session_id, now,
            )

        return agent_pid, agent_comm, app_name, agent_id, session_id


addons = [AgentGatewayAddon()]
