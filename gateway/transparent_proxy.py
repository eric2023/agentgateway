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
#
# All traffic reaching this proxy is from cgroup-isolated Agent processes,
# so every connection is MITM'd — no AI_HOST_PATTERNS filtering needed.

import os
import sys
import socket
import select
import ssl
import struct
import threading
import json
import uuid
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agentgatewayd as gw

HOST = "127.0.0.1"
PORT = 8444

SO_ORIGINAL_DST = 80
SOL_IP = 0

AGENT_ID = os.environ.get("AGENTGATEWAY_AGENT_ID", f"agent-{uuid.uuid4().hex[:8]}")
SESSION_ID = os.environ.get("AGENTGATEWAY_SESSION_ID", f"session-{uuid.uuid4().hex[:8]}")
REQUEST_ID_PREFIX = f"req-{uuid.uuid4().hex[:8]}"


def _orig_dst(sock):
    """Original destination (ip, port) of a REDIRECTed connection, else (None, None)."""
    try:
        data = sock.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16)
        port = int.from_bytes(data[2:4], "big")
        ip = socket.inet_ntoa(data[4:8])
        return ip, port
    except Exception:
        return None, None


def extract_sni(data):
    """Extract the SNI hostname from a TLS ClientHello record, or None."""
    try:
        if len(data) < 6 or data[0] != 0x16:  # handshake record
            return None
        # handshake: [0x16][ver 2][len 2][hs_type 1][hs_len 3]...
        if data[5] != 0x01:  # ClientHello
            return None
        pos = 11 + 32  # skip type+len(4) + version(2) + random(32) => record hdr(5) + hs hdr(4) + ver(2) + random(32)
        if pos >= len(data):
            return None
        sid_len = data[pos]
        pos += 1 + sid_len
        if pos + 2 > len(data):
            return None
        cs_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2 + cs_len
        if pos + 1 > len(data):
            return None
        comp_len = data[pos]
        pos += 1 + comp_len
        if pos + 2 > len(data):
            return None
        ext_total = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        ext_end = min(pos + ext_total, len(data))
        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0 and pos + 5 <= len(data):  # server_name
                name_type = data[pos + 2]
                name_len = int.from_bytes(data[pos + 3:pos + 5], "big")
                if name_type == 0:  # host_name
                    return data[pos + 5:pos + 5 + name_len].decode("utf-8", "replace")
            pos += ext_len
    except Exception:
        return None
    return None


def _redact_headers(headers):
    out = {}
    for k, v in headers.items():
        if k.lower() in ("authorization", "x-api-key", "cookie", "x-goog-api-key"):
            out[k] = (v[:20] + "***REDACTED***") if v else v
        else:
            out[k] = v
    return out


def _dechunk(data):
    result = b""
    pos = 0
    while pos < len(data):
        crlf = data.find(b"\r\n", pos)
        if crlf == -1:
            break
        try:
            size = int(data[pos:crlf].strip(), 16)
        except ValueError:
            break
        if size == 0:
            break
        result += data[crlf + 2:crlf + 2 + size]
        pos = crlf + 2 + size + 2
    return result


def _read_request(rfile):
    """Read one HTTP request (line + headers + body) from a buffered reader."""
    line = rfile.readline(8192)
    if not line:
        return None
    parts = line.decode("utf-8", errors="replace").strip().split(" ", 2)
    if len(parts) != 3:
        return None
    method, path, _version = parts
    headers = {}
    while True:
        l = rfile.readline(8192)
        if not l or l in (b"\r\n", b"\n"):
            break
        s = l.decode("utf-8", errors="replace").rstrip("\r\n")
        if ":" in s:
            k, v = s.split(":", 1)
            headers[k.strip()] = v.strip()
    body = b""
    try:
        cl = int(headers.get("Content-Length", "0"))
    except ValueError:
        cl = 0
    if cl > 0:
        body = rfile.read(cl)
    return method, path, headers, body


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


def _blind_tunnel(client, host, port, initial=b""):
    try:
        remote = socket.create_connection((host, port), timeout=30)
    except Exception as e:
        gw.log(f"[TPROXY] blind tunnel to {host}:{port} failed: {e}")
        return
    try:
        if initial:
            remote.sendall(initial)
        # Use poll() — select() fails with "filedescriptor out of range"
        # when FD numbers exceed 1024 (common in long-running processes).
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

def _mitm(client, host, rfile_hint=b""):
    cert_path, key_path = gw.generate_cert_for_host(host)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        tls = ctx.wrap_socket(client, server_side=True)
    except ssl.SSLError as e:
        gw.log(f"[TPROXY] TLS wrap {host} failed: {e}")
        return

    try:
        rfile = tls.makefile("rb", buffering=8192)
        req = _read_request(rfile)
        if not req:
            return
        method, path, headers, body = req
        t0 = time.time()

        is_ai, confidence, signals, detail = gw.detect_ai_request(method, path, headers, body)
        request_id = f"{REQUEST_ID_PREFIX}-{uuid.uuid4().hex[:6]}"

        status = 0
        resp_body = b""
        fwd_ok = True
        try:
            status, resp_headers, resp_body = _forward(host, 443, method, path, headers, body)
        except Exception as e:
            fwd_ok = False
            gw.log(f"[TPROXY] forward {host}{path} failed: {e}")

        latency_ms = int((time.time() - t0) * 1000)

        if is_ai:
            event = {
                "event": "ai_request_audited",
                "decision": "AUDIT",
                "app_name": "transparent",
                "session_id": SESSION_ID,
                "agent_id": AGENT_ID,
                "request_id": request_id,
                "method": method,
                "host": host,
                "port": 443,
                "path": path,
                "model": detail.get("model", ""),
                "confidence": confidence,
                "signals": signals,
                "preview": detail.get("preview", ""),
                "prompt_len": detail.get("prompt_len", 0),
                "request_headers": _redact_headers(headers),
                "request_body": body.decode("utf-8", errors="replace")[:2000],
                "stream_mode": "stream" in body.decode("utf-8", errors="replace").lower(),
                "response_status": status if fwd_ok else 0,
                "latency_ms": latency_ms,
                "source": "transparent_proxy",
                "summary": f"AI request audited & forwarded: {method} {host}{path} model={detail.get('model','')}",
            }
            gw.audit_log(event)

        # Return the upstream response to the client.
        if fwd_ok and status:
            reason = "OK"
            try:
                tls.sendall(f"HTTP/1.1 {status} {reason}\r\n".encode())
                for k, v in resp_headers:
                    tls.sendall(f"{k}: {v}\r\n".encode())
                tls.sendall(b"Connection: close\r\n\r\n")
                tls.sendall(resp_body)
            except (OSError, ssl.SSLError):
                pass
        else:
            try:
                tls.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except (OSError, ssl.SSLError):
                pass
    finally:
        try:
            tls.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            tls.close()
        except OSError:
            pass


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
                client.recv(4096)  # consume the peeked bytes' copy is fine; we peeked so still buffered
                _blind_tunnel(client, orig_ip, orig_port)
            return
        # All cgroup-isolated traffic is MITM'd — no host filtering needed.
        gw.log(f"[TPROXY] MITM {sni} from {addr[0]}:{addr[1]}")
        _mitm(client, sni)
    except (OSError, ssl.SSLError):
        pass
    finally:
        try:
            client.close()
        except OSError:
            pass


def main():
    gw.audit_init()
    gw.load_ca()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(128)
    gw.log(f"[TPROXY] AgentGateway transparent proxy listening on {HOST}:{PORT}")
    gw.log(f"[TPROXY] agent={AGENT_ID} session={SESSION_ID}")
    while True:
        try:
            client, addr = srv.accept()
        except OSError:
            break
        threading.Thread(target=_handle, args=(client, addr), daemon=True).start()


if __name__ == "__main__":
    main()
