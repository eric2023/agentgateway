#!/bin/bash
# start.sh — Start AgentGateway daemon + Dashboard in one shot.
#
# Usage:
#   ./start.sh          # start both (foreground, Ctrl+C to stop both)
#   ./start.sh -d       # start in background (daemon mode)
#   ./start.sh stop     # stop both
#   ./start.sh restart  # restart both
#
# The gateway manages gsettings system proxy lifecycle (manual → restore on
# exit).  The dashboard reads audit/audit.jsonl live and needs no restart.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
GATEWAY="$PROJECT_DIR/gateway/agentgatewayd.py"
DASHBOARD="$PROJECT_DIR/dashboard/dashboard.py"
LOG_DIR="$PROJECT_DIR/logs"
GATEWAY_LOG="$LOG_DIR/gateway.log"
DASHBOARD_LOG="$LOG_DIR/dashboard.log"
GATEWAY_PIDFILE="$LOG_DIR/gateway.pid"
DASHBOARD_PIDFILE="$LOG_DIR/dashboard.pid"

PYTHON="$(command -v python3 || true)"
[[ -z "$PYTHON" ]] && PYTHON="/home/ut000520@uos/.pyenv/shims/python3"

mkdir -p "$LOG_DIR"

# ─── helpers ────────────────────────────────────────────────────────────────

is_running() {
    local pidfile="$1"
    [[ -f "$pidfile" ]] || return 1
    local pid
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    [[ -n "$pid" ]] || return 1
    kill -0 "$pid" 2>/dev/null
}

stop_proc() {
    local name="$1" pidfile="$2"
    if is_running "$pidfile"; then
        local pid
        pid="$(cat "$pidfile")"
        echo "[start.sh] Stopping $name (pid=$pid) ..."
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 10); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.3
        done
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
        echo "[start.sh] $name stopped."
    else
        echo "[start.sh] $name not running."
    fi
    rm -f "$pidfile"
}

start_proc() {
    local name="$1" script="$2" pidfile="$3" logfile="$4"
    if is_running "$pidfile"; then
        echo "[start.sh] $name already running (pid=$(cat "$pidfile"))."
        return 0
    fi
    echo "[start.sh] Starting $name ..."
    "$PYTHON" "$script" >>"$logfile" 2>&1 &
    local pid=$!
    echo "$pid" > "$pidfile"
    echo "[start.sh] $name started (pid=$pid, log=$logfile)."
}

# ─── actions ────────────────────────────────────────────────────────────────

do_stop() {
    stop_proc "gateway"  "$GATEWAY_PIDFILE"
    stop_proc "dashboard" "$DASHBOARD_PIDFILE"
}

do_start() {
    # Stop existing instances first (clean restart).
    do_stop 2>/dev/null || true

    start_proc "gateway"   "$GATEWAY"   "$GATEWAY_PIDFILE"   "$GATEWAY_LOG"
    sleep 1.5   # let gateway bind the port + set gsettings before dashboard
    start_proc "dashboard" "$DASHBOARD" "$DASHBOARD_PIDFILE" "$DASHBOARD_LOG"

    echo
    echo "[start.sh] ─────────────────────────────────────"
    echo "[start.sh] Gateway:   http://127.0.0.1:8443  (proxy)"
    echo "[start.sh] Dashboard: http://127.0.0.1:9090  (web UI)"
    echo "[start.sh] Logs:      $GATEWAY_LOG"
    echo "[start.sh]             $DASHBOARD_LOG"
    echo "[start.sh] Stop:       $0 stop"
    echo "[start.sh] ─────────────────────────────────────"
}

do_foreground() {
    # Stop any background instances.
    do_stop 2>/dev/null || true

    echo "[start.sh] Starting gateway (foreground) ..."
    "$PYTHON" "$GATEWAY" >>"$GATEWAY_LOG" 2>&1 &
    GW_PID=$!
    echo "$GW_PID" > "$GATEWAY_PIDFILE"
    echo "[start.sh] Gateway pid=$GW_PID"

    sleep 1.5

    echo "[start.sh] Starting dashboard (foreground) ..."
    "$PYTHON" "$DASHBOARD" >>"$DASHBOARD_LOG" 2>&1 &
    DASH_PID=$!
    echo "$DASHBOARD_PIDFILE" > /dev/null
    echo "$DASH_PID" > "$DASHBOARD_PIDFILE"
    echo "[start.sh] Dashboard pid=$DASH_PID"

    echo
    echo "[start.sh] Gateway:   http://127.0.0.1:8443  (proxy)"
    echo "[start.sh] Dashboard: http://127.0.0.1:9090  (web UI)"
    echo "[start.sh] Press Ctrl+C to stop both."
    echo

    cleanup() {
        echo
        echo "[start.sh] Stopping ..."
        kill "$GW_PID" 2>/dev/null || true
        kill "$DASH_PID" 2>/dev/null || true
        rm -f "$GATEWAY_PIDFILE" "$DASHBOARD_PIDFILE"
        wait "$GW_PID" 2>/dev/null || true
        wait "$DASH_PID" 2>/dev/null || true
        echo "[start.sh] Stopped."
    }
    trap cleanup EXIT INT TERM

    wait
}

do_status() {
    if is_running "$GATEWAY_PIDFILE"; then
        echo "[start.sh] Gateway:   running (pid=$(cat "$GATEWAY_PIDFILE"))"
    else
        echo "[start.sh] Gateway:   stopped"
    fi
    if is_running "$DASHBOARD_PIDFILE"; then
        echo "[start.sh] Dashboard: running (pid=$(cat "$DASHBOARD_PIDFILE"))"
    else
        echo "[start.sh] Dashboard: stopped"
    fi
}

# ─── main ───────────────────────────────────────────────────────────────────

case "${1:-start}" in
    start)   do_start ;;
    -d|daemon) do_start ;;
    fg|foreground) do_foreground ;;
    stop)    do_stop ;;
    restart) do_start ;;
    status)  do_status ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|fg}"
        echo
        echo "  start    Start gateway + dashboard in background (default)"
        echo "  -d       Same as start (daemon mode)"
        echo "  fg       Start in foreground (Ctrl+C to stop both)"
        echo "  stop     Stop both"
        echo "  restart  Restart both"
        echo "  status   Show running status"
        exit 1
        ;;
esac
