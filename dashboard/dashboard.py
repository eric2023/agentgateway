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
AgentGateway Dashboard — Zero-dependency web UI for AI request monitoring.

Built with Python stdlib http.server + Chart.js (CDN).
Reads audit events from audit/audit.db (SQLite WAL) and displays:
- Real-time stats (blocked/forwarded/audited/total)
- Event timeline chart
- Model distribution chart
- Requests list (AxonHub-style: time, status, model, latency, tokens)
- Request detail view (headers, body, response, token usage)
- Trace view (session-grouped request timeline)

Run: python3 dashboard.py
Open: http://127.0.0.1:9090
"""

import os
import json
import time
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_DB = os.path.join(BASE_DIR, "audit", "audit.db")
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 9090

# Local timezone (Asia/Shanghai = UTC+8)
LOCAL_TZ = timezone(timedelta(hours=8))


def get_db():
    """Get a SQLite connection (WAL mode, read-only queries)."""
    conn = sqlite3.connect(AUDIT_DB, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _parse_json(val):
    """Safely parse a JSON string stored in SQLite, return dict/list or None."""
    if not val:
        return None
    if isinstance(val, (dict, list)):
        return val
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return None


def _row_to_event(row):
    """Convert a SQLite Row to an event dict (compatible with old JSONL format)."""
    if row is None:
        return {}
    d = dict(row)
    # Parse JSON fields stored as TEXT
    d["signals"] = _parse_json(d.get("signals")) or []
    d["request_headers"] = _parse_json(d.get("request_headers")) or {}
    d["request_body"] = _parse_json(d.get("request_body"))
    d["response_headers"] = _parse_json(d.get("response_headers")) or {}
    d["response_body"] = _parse_json(d.get("response_body"))
    d["token_usage"] = _parse_json(d.get("token_usage")) or {}
    d["stream_mode"] = bool(d.get("stream_mode", 0))
    return d


def to_local_time_str(ts_str):
    """Convert UTC ISO timestamp to local time string (YYYY-MM-DD HH:MM:SS)."""
    if not ts_str:
        return "?"
    try:
        dt = datetime.fromisoformat(ts_str)
        dt_local = dt.astimezone(LOCAL_TZ)
        return dt_local.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts_str[:19].replace("T", " ")


def to_local_time_short(ts_str):
    """Convert UTC ISO timestamp to short local time (HH:MM:SS)."""
    if not ts_str:
        return "?"
    try:
        dt = datetime.fromisoformat(ts_str)
        dt_local = dt.astimezone(LOCAL_TZ)
        return dt_local.strftime("%H:%M:%S")
    except Exception:
        return ts_str[11:19] if len(ts_str) >= 19 else ts_str


def get_stats():
    """Compute aggregate stats from SQLite — O(1) queries, not O(n) scan."""
    db = get_db()
    try:
        total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        blocked = db.execute("SELECT COUNT(*) FROM events WHERE decision='BLOCK'").fetchone()[0]
        forwarded = db.execute("SELECT COUNT(*) FROM events WHERE decision='FORWARD'").fetchone()[0]
        audited = db.execute("SELECT COUNT(*) FROM events WHERE decision='AUDIT'").fetchone()[0]

        # Host distribution (top 20)
        host_rows = db.execute("""
            SELECT host, decision, COUNT(*) as cnt
            FROM events WHERE decision IN ('BLOCK','FORWARD','AUDIT')
            GROUP BY host, decision ORDER BY cnt DESC LIMIT 20
        """).fetchall()
        hosts = [{"host": r["host"], "decision": r["decision"], "count": r["cnt"]}
                 for r in host_rows]

        # Model distribution (top 20)
        model_rows = db.execute("""
            SELECT model, COUNT(*) as cnt
            FROM events WHERE decision IN ('BLOCK','AUDIT') AND model IS NOT NULL AND model != ''
            GROUP BY model ORDER BY cnt DESC LIMIT 20
        """).fetchall()
        models = [{"model": r["model"], "count": r["cnt"]} for r in model_rows]

        # Timeline (by minute, last 24h)
        cutoff = time.time() - 86400
        tl_rows = db.execute("""
            SELECT ts_unix, decision FROM events
            WHERE ts_unix > ? AND decision IN ('BLOCK','FORWARD','AUDIT')
        """, (cutoff,)).fetchall()
        timeline = defaultdict(lambda: {"blocked": 0, "forwarded": 0, "audited": 0})
        for r in tl_rows:
            ts = r["ts_unix"]
            if ts:
                minute = datetime.fromtimestamp(ts, tz=LOCAL_TZ).strftime("%H:%M")
                decision = (r["decision"] or "").lower()
                if decision in ("block", "forward", "audit"):
                    timeline[minute][decision] += 1
        tl_sorted = [{"minute": k, "blocked": v["blocked"],
                      "forwarded": v["forwarded"], "audited": v["audited"]}
                     for k, v in sorted(timeline.items())]

        return {
            "total": total,
            "blocked_count": blocked,
            "forwarded_count": forwarded,
            "audited_count": audited,
            "hosts": hosts,
            "models": models,
            "timeline": tl_sorted,
        }
    finally:
        db.close()


def extract_tool_calls(req_body, resp_body):
    """Extract tool call info from request/response bodies.

    Returns:
        tools_defined: list of tool names defined in the request
        tool_calls: list of {tool_name, arguments, result_preview, call_id}
        has_skill: whether any skill tool was invoked
    """
    tools_defined = []
    tool_calls = []

    # Extract tool definitions from request
    if req_body and isinstance(req_body, dict):
        tools = req_body.get("tools") or req_body.get("functions") or []
        for t in tools:
            if isinstance(t, dict):
                fn = t.get("function", t)
                name = fn.get("name", "")
                if name:
                    tools_defined.append(name)

        # Extract assistant tool_calls and tool results from messages
        messages = req_body.get("messages", [])
        # Map call_id -> tool result
        tool_results = {}
        for m in messages:
            if m.get("role") == "tool" and m.get("tool_call_id"):
                content = m.get("content", "")
                tool_results[m["tool_call_id"]] = content[:200] if content else ""

        for m in messages:
            if m.get("role") == "assistant" and m.get("tool_calls"):
                for tc in m["tool_calls"]:
                    fn = tc.get("function", {})
                    name = fn.get("name", "")
                    args = fn.get("arguments", "")
                    call_id = tc.get("id", "")
                    result = tool_results.get(call_id, "")
                    # Try to parse args as JSON for cleaner display
                    try:
                        args_parsed = json.loads(args) if isinstance(args, str) else args
                    except (json.JSONDecodeError, TypeError):
                        args_parsed = {"raw": args[:200]} if args else {}
                    tool_calls.append({
                        "tool_name": name,
                        "arguments": args_parsed,
                        "result_preview": result,
                        "call_id": call_id,
                    })

    # Extract tool_calls from response body (assistant's new tool calls)
    if resp_body and isinstance(resp_body, dict):
        choices = resp_body.get("choices", [])
        for c in choices:
            msg = c.get("message", {})
            if msg.get("tool_calls"):
                for tc in msg["tool_calls"]:
                    fn = tc.get("function", {})
                    name = fn.get("name", "")
                    args = fn.get("arguments", "")
                    call_id = tc.get("id", "")
                    try:
                        args_parsed = json.loads(args) if isinstance(args, str) else args
                    except (json.JSONDecodeError, TypeError):
                        args_parsed = {"raw": args[:200]} if args else {}
                    # Avoid duplicates
                    if not any(tc2["call_id"] == call_id for tc2 in tool_calls):
                        tool_calls.append({
                            "tool_name": name,
                            "arguments": args_parsed,
                            "result_preview": "",
                            "call_id": call_id,
                        })

    has_skill = any(tc["tool_name"] == "skill" for tc in tool_calls)
    return tools_defined, tool_calls, has_skill


def get_ai_requests(limit=200):
    """Get AI request events with matching responses — SQL JOIN, not O(n) scan."""
    db = get_db()
    try:
        rows = db.execute("""
            SELECT r.*, resp.response_status, resp.response_headers,
                   resp.response_body, resp.token_usage, resp.latency_ms
            FROM events r
            LEFT JOIN events resp ON r.request_id = resp.request_id
                AND resp.event = 'ai_response'
            WHERE r.event = 'ai_request_audited'
            ORDER BY r.ts_unix DESC
            LIMIT ?
        """, (limit,)).fetchall()

        result = []
        for row in rows:
            req = _row_to_event(row)
            # Response fields come from the JOIN alias — extract from row directly
            resp_body = _parse_json(row["response_body"]) if row["response_body"] else None
            resp_headers = _parse_json(row["response_headers"]) if row["response_headers"] else {}
            token_usage = _parse_json(row["token_usage"]) if row["token_usage"] else {}
            has_resp = row["response_status"] is not None

            item = {
                "request_id": req.get("request_id", ""),
                "ts": req.get("ts", ""),
                "method": req.get("method", "?"),
                "host": req.get("host", "?"),
                "path": req.get("path", "?"),
                "model": req.get("model", "?") or "?",
                "confidence": req.get("confidence", 0),
                "signals": req.get("signals", []),
                "preview": req.get("preview", ""),
                "stream_mode": req.get("stream_mode", False),
                "session_id": req.get("session_id", ""),
                "agent_id": req.get("agent_id", ""),
                "app_name": req.get("app_name", "unknown"),
                "request_body": req.get("request_body"),
                "request_body_raw": (json.dumps(req.get("request_body"), ensure_ascii=False)[:2000]
                                     if req.get("request_body") else ""),
                "response_status": row["response_status"],
                "response_headers": resp_headers,
                "response_body": resp_body,
                "response_body_raw": (json.dumps(resp_body, ensure_ascii=False)[:4000]
                                      if resp_body else ""),
                "token_usage": token_usage,
                "latency_ms": row["latency_ms"],
                "has_response": has_resp,
                "error": None,
            }
            item["tools_defined"], item["tool_calls"], item["has_skill"] = \
                extract_tool_calls(req.get("request_body"), resp_body)
            result.append(item)

        return result
    finally:
        db.close()


def _get_conversation_key(event):
    """Extract a conversation key from an AI request event.

    A conversation is identified by:
    - The app_name (process name, e.g. "uos-ai-assistant", "chrome", "python3")
    - The first user message content

    Returns: (app_name, first_user_msg) tuple.
    """
    app_name = event.get("app_name", "Unknown") or "Unknown"
    rb = event.get("request_body")
    if not rb or not isinstance(rb, dict):
        return (app_name, "")

    messages = rb.get("messages", [])
    if not messages:
        return (app_name, "")

    # Get first user message
    first_user = ""
    for m in messages:
        if m.get("role") == "user":
            c = m.get("content", "")
            if isinstance(c, str):
                first_user = c[:80]
            elif isinstance(c, list):
                for p in c:
                    if isinstance(p, dict) and p.get("type") == "text":
                        first_user = p.get("text", "")[:80]
                        break
            break

    return (app_name, first_user)


def get_traces(limit=50):
    """Group AI requests by conversation for trace view — SQL queries, not O(n) scan."""
    db = get_db()
    try:
        # Get recent AI request events with matching responses
        rows = db.execute("""
            SELECT r.*, resp.response_status, resp.response_body, resp.token_usage, resp.latency_ms
            FROM events r
            LEFT JOIN events resp ON r.request_id = resp.request_id
                AND resp.event = 'ai_response'
            WHERE r.event = 'ai_request_audited'
            ORDER BY r.ts_unix DESC
            LIMIT 1000
        """).fetchall()

        events = []
        for row in rows:
            evt = _row_to_event(row)
            # Merge response fields into the event for trace processing
            evt["response_status"] = row["response_status"]
            evt["response_body"] = _parse_json(row["response_body"]) if row["response_body"] else None
            evt["token_usage"] = _parse_json(row["token_usage"]) if row["token_usage"] else {}
            evt["latency_ms"] = row["latency_ms"]
            events.append(evt)

        # Group by conversation key = (app_name, first_user_msg)
        convos = defaultdict(list)
        for e in events:
            key = _get_conversation_key(e)
            convos[key].append(e)

        traces = []
        for key, evts in convos.items():
            app_name, first_user = key
            evts.sort(key=lambda x: x.get("ts", ""))

            # Skip browser prediction conversations — not real agent sessions
            if app_name == "Browser-Predict":
                continue

            ai_reqs = evts
            if not ai_reqs:
                continue

            total_tokens = 0
            all_tool_calls = []
            all_tools_defined = set()
            has_skill = False
            for e in ai_reqs:
                tu = e.get("token_usage", {})
                total_tokens += tu.get("total_tokens", 0) if tu else 0
                req_body = e.get("request_body")
                resp_body = e.get("response_body")
                tools_def, tool_calls, skill = extract_tool_calls(req_body, resp_body)
                if tool_calls:
                    all_tool_calls.append({
                        "ts": e.get("ts", ""),
                        "event": e.get("event", ""),
                        "tool_calls": tool_calls,
                    })
                for t in tools_def:
                    all_tools_defined.add(t)
                if skill:
                    has_skill = True

            traces.append({
                "conversation_id": f"{app_name}:{first_user[:30]}",
                "session_id": ai_reqs[0].get("session_id", ""),
                "agent_id": ai_reqs[0].get("agent_id", ""),
                "app_name": app_name,
                "first_user_msg": first_user,
                "request_count": len(ai_reqs),
                "first_ts": ai_reqs[0].get("ts", ""),
                "last_ts": ai_reqs[-1].get("ts", ""),
                "total_tokens": total_tokens,
                "tools_defined": sorted(all_tools_defined),
                "tool_call_count": sum(len(tc["tool_calls"]) for tc in all_tool_calls),
                "has_skill": has_skill,
                "all_tool_calls": all_tool_calls,
                "events": evts,
            })

        # Sort by first_ts descending (newest first)
        traces.sort(key=lambda t: t["first_ts"], reverse=True)
        return traces[:limit]
    finally:
        db.close()


def esc(s):
    """HTML-escape a string."""
    if s is None:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# Load HTML template
_TEMPLATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_template.html")
_html_template = ""
if os.path.exists(_TEMPLATE_PATH):
    with open(_TEMPLATE_PATH, "r") as f:
        _html_template = f.read()


def render_html(stats, requests):
    """Render the full dashboard HTML page."""
    if not _html_template:
        return "<h1>Dashboard template not found</h1>"
    html = _html_template
    html = html.replace("{{TOTAL}}", str(stats.get("total", 0)))
    html = html.replace("{{BLOCKED}}", str(stats.get("blocked_count", 0)))
    html = html.replace("{{FORWARDED}}", str(stats.get("forwarded_count", 0)))
    html = html.replace("{{AUDITED}}", str(stats.get("audited_count", 0)))
    return html


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress access logs

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/data":
            stats = get_stats()
            requests = get_ai_requests(200)
            traces = get_traces(50)

            # Convert timestamps for display
            for r in requests:
                r["ts"] = to_local_time_str(r.get("ts", ""))
            for t in traces:
                t["first_ts"] = to_local_time_str(t.get("first_ts", ""))
                t["last_ts"] = to_local_time_str(t.get("last_ts", ""))
                for e in t["events"]:
                    e["ts"] = to_local_time_short(e.get("ts", ""))
            data = {
                "stats": stats,
                "requests": requests[:200],
                "traces": traces[:50],
                "total_events": stats["total"],
            }
            body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/api/refresh":
            stats = get_stats()
            db = get_db()
            try:
                blocked = [_row_to_event(r) for r in db.execute(
                    "SELECT * FROM events WHERE decision='BLOCK' ORDER BY id DESC LIMIT 10").fetchall()]
                forwarded = [_row_to_event(r) for r in db.execute(
                    "SELECT * FROM events WHERE decision='FORWARD' ORDER BY id DESC LIMIT 5").fetchall()]
                audited = [_row_to_event(r) for r in db.execute(
                    "SELECT * FROM events WHERE decision='AUDIT' ORDER BY id DESC LIMIT 10").fetchall()]
            finally:
                db.close()
            data = {
                "stats": stats,
                "recent_blocked": blocked,
                "recent_forwarded": forwarded,
                "recent_audited": audited,
            }
            body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/api/events":
            stats = get_stats()
            db = get_db()
            try:
                blocked = [_row_to_event(r) for r in db.execute(
                    "SELECT * FROM events WHERE decision='BLOCK' ORDER BY id DESC LIMIT 100").fetchall()]
                audited = [_row_to_event(r) for r in db.execute(
                    "SELECT * FROM events WHERE decision='AUDIT' ORDER BY id DESC LIMIT 100").fetchall()]
                forwarded = [_row_to_event(r) for r in db.execute(
                    "SELECT * FROM events WHERE decision='FORWARD' ORDER BY id DESC LIMIT 50").fetchall()]
            finally:
                db.close()
            data = {
                "stats": stats,
                "blocked": blocked,
                "audited": audited,
                "forwarded": forwarded,
                "total_events": stats["total"],
            }
            body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/" or path == "/index.html":
            stats = get_stats()
            requests = get_ai_requests(200)
            html = render_html(stats, requests).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(html))
            self.end_headers()
            self.wfile.write(html)

        else:
            self.send_response(404)
            self.end_headers()


class ThreadingHTTPServer(HTTPServer):
    pass


def main():
    from socketserver import ThreadingMixIn
    class ThreadedServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    print(f"{'='*50}")
    print(f"AgentGateway Dashboard v3.0 (SQLite)")
    print(f"  URL:   http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    print(f"  DB:    {AUDIT_DB}")
    print(f"  TZ:    Asia/Shanghai (UTC+8)")
    print(f"{'='*50}")

    server = ThreadedServer((DASHBOARD_HOST, DASHBOARD_PORT), DashboardHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Dashboard stopped.")
        server.shutdown()


if __name__ == "__main__":
    main()
