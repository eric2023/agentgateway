#!/usr/bin/env python3
"""
AgentGateway Dashboard — Zero-dependency web UI for AI request monitoring.

Built with Python stdlib http.server + Chart.js (CDN).
Reads audit events from audit/audit.jsonl and displays:
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
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_LOG = os.path.join(BASE_DIR, "audit", "audit.jsonl")
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 9090

# Local timezone (Asia/Shanghai = UTC+8)
LOCAL_TZ = timezone(timedelta(hours=8))


def read_audit_events():
    """Read all audit events from the JSONL log."""
    events = []
    if not os.path.exists(AUDIT_LOG):
        return events
    with open(AUDIT_LOG, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


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


def get_stats(events):
    """Compute aggregate stats from events."""
    total = len(events)
    blocked = [e for e in events if e.get("decision") == "BLOCK"]
    forwarded = [e for e in events if e.get("decision") == "FORWARD"]
    audited = [e for e in events if e.get("decision") == "AUDIT"]

    host_counter = Counter()
    for e in blocked + forwarded + audited:
        host = e.get("host", "unknown")
        decision = e.get("decision", "?")
        host_counter[(host, decision)] += 1

    model_counter = Counter()
    for e in blocked + audited:
        model = e.get("model", "unknown")
        if model:
            model_counter[model] += 1

    timeline = defaultdict(lambda: {"blocked": 0, "forwarded": 0, "audited": 0})
    for e in blocked + forwarded + audited:
        ts = e.get("ts_unix", 0)
        if ts:
            minute = datetime.fromtimestamp(ts, tz=LOCAL_TZ).strftime("%H:%M")
            decision = e.get("decision", "").lower()
            if decision == "block":
                timeline[minute]["blocked"] += 1
            elif decision == "forward":
                timeline[minute]["forwarded"] += 1
            elif decision == "audit":
                timeline[minute]["audited"] += 1
    return {
        "total": total,
        "blocked_count": len(blocked),
        "forwarded_count": len(forwarded),
        "audited_count": len(audited),
        "hosts": [
            {"host": h, "decision": d, "count": c}
            for (h, d), c in host_counter.most_common(20)
        ],
        "models": [
            {"model": m, "count": c}
            for m, c in model_counter.most_common(20)
        ],
        "timeline": [
            {"minute": k, "blocked": v["blocked"], "forwarded": v["forwarded"], "audited": v["audited"]}
            for k, v in sorted(timeline.items())
        ],
    }

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
def get_ai_requests(events):
    """Get AI request events (request + matching response) for the Requests table."""
    # Build request-response pairs by request_id
    requests_by_id = {}
    responses_by_id = {}
    for e in events:
        rid = e.get("request_id")
        if not rid:
            continue
        ev = e.get("event", "")
        if ev == "ai_request_audited":
            requests_by_id[rid] = e
        elif ev == "ai_response":
            responses_by_id[rid] = e

    # Merge into list
    result = []
    for rid, req in requests_by_id.items():
        resp = responses_by_id.get(rid, {})
        result.append({
            "request_id": rid,
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
            "request_body_raw": req.get("request_body_raw", ""),
            "response_status": resp.get("response_status"),
            "response_headers": resp.get("response_headers", {}),
            "response_body": resp.get("response_body"),
            "response_body_raw": resp.get("response_body_raw", ""),
            "token_usage": resp.get("token_usage", {}),
            "latency_ms": resp.get("latency_ms"),
            "has_response": bool(resp),
            "error": resp.get("error") if resp else None,
        })
        # Extract tool call info
        result[-1]["tools_defined"], result[-1]["tool_calls"], result[-1]["has_skill"] = \
            extract_tool_calls(req.get("request_body"), resp.get("response_body"))

    # Sort by timestamp descending
    result.sort(key=lambda x: x.get("ts", ""), reverse=True)
    return result


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


def get_traces(events):
    """Group AI requests by conversation for trace view.

    A conversation = sequence of requests with the same app_name (process name)
    and the same first user message. Message count grows within a conversation
    as the agent sends tool calls and receives results.
    Browser prediction requests (app_name="Browser-Predict") are filtered out.
    """
    # Collect all AI request/response events
    ai_events = [e for e in events
                 if e.get("event") in ("ai_request_audited", "ai_response", "ai_forward_error")]

    # Group by conversation key = (app_name, first_user_msg)
    convos = defaultdict(list)
    for e in ai_events:
        if e.get("event") == "ai_request_audited":
            key = _get_conversation_key(e)
        else:
            # Response/error events: find the matching request by request_id
            rid = e.get("request_id", "")
            key = None
            for req_e in ai_events:
                if req_e.get("request_id") == rid and req_e.get("event") == "ai_request_audited":
                    key = _get_conversation_key(req_e)
                    break
            if key is None:
                key = ("Unknown", "")
        convos[key].append(e)

    traces = []
    for key, evts in convos.items():
        app_name, first_user = key
        evts.sort(key=lambda x: x.get("ts", ""))

        # Skip browser prediction conversations — not real agent sessions
        if app_name == "Browser-Predict":
            continue

        ai_reqs = [e for e in evts if e.get("event") == "ai_request_audited"]
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
    return traces


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


def render_html(stats, events):
    """Render the full dashboard HTML page."""
    host_rows = "".join(
        f'<tr><td>{esc(h["host"])}</td><td><span class="badge {h["decision"].lower()}">{h["decision"]}</span></td><td>{h["count"]}</td></tr>'
        for h in stats["hosts"]
    )
    if not host_rows:
        host_rows = '<tr><td colspan="3" class="empty">暂无</td></tr>'

    html = _html_template
    html = html.replace("__TOTAL__", str(stats["total"]))
    html = html.replace("__BLOCKED__", str(stats["blocked_count"]))
    html = html.replace("__FORWARDED__", str(stats["forwarded_count"]))
    html = html.replace("__AUDITED__", str(stats["audited_count"]))
    html = html.replace("__HOST_ROWS__", host_rows)
    html = html.replace("__TIMELINE_DATA__", json.dumps(stats["timeline"]))
    html = html.replace("__MODEL_DATA__", json.dumps(stats["models"]))
    return html


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/data":
            events = read_audit_events()
            stats = get_stats(events)
            requests = get_ai_requests(events)
            traces = get_traces(events)
            # Convert timestamps to local time for display
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
                "total_events": len(events),
            }
            body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/api/refresh":
            events = read_audit_events()
            stats = get_stats(events)
            data = {
                "stats": stats,
                "recent_blocked": [e for e in events if e.get("decision") == "BLOCK"][-10:],
                "recent_forwarded": [e for e in events if e.get("decision") == "FORWARD"][-5:],
                "recent_audited": [e for e in events if e.get("decision") == "AUDIT"][-10:],
            }
            body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/api/events":
            events = read_audit_events()
            stats = get_stats(events)
            blocked = [e for e in events if e.get("decision") == "BLOCK"]
            audited = [e for e in events if e.get("decision") == "AUDIT"]
            forwarded = [e for e in events if e.get("decision") == "FORWARD"]
            data = {
                "stats": stats,
                "blocked": blocked[-100:],
                "audited": audited[-100:],
                "forwarded": forwarded[-50:],
                "total_events": len(events),
            }
            body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/" or path == "/index.html":
            events = read_audit_events()
            stats = get_stats(events)
            html = render_html(stats, events).encode("utf-8")
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
    print(f"AgentGateway Dashboard v2.0")
    print(f"  URL:   http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    print(f"  Audit: {AUDIT_LOG}")
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
