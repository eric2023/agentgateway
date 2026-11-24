#!/bin/bash
# start.sh — Start AgentGateway transparent proxy + Dashboard in one shot.
#
# Usage:
#   ./start.sh start      # start transparent proxy + dashboard (background)
#   ./start.sh -d         # same as start (daemon mode)
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
    stop_proc "transparent-proxy" "$TPROXY_PIDFILE"
    stop_proc "dashboard" "$DASHBOARD_PIDFILE"
}

do_start() {
    # Stop existing instances first (clean restart).
    do_stop 2>/dev/null || true

    start_proc "transparent-proxy" "$TPROXY"   "$TPROXY_PIDFILE"   "$TPROXY_LOG"
    sleep 1.5   # let tproxy bind the port before dashboard
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

do_foreground() {
    # Stop any background instances.
    do_stop 2>/dev/null || true

    echo "[start.sh] Starting transparent proxy (foreground) ..."
    "$PYTHON" "$TPROXY" >>"$TPROXY_LOG" 2>&1 &
    TP_PID=$!
    echo "$TP_PID" > "$TPROXY_PIDFILE"
    echo "[start.sh] Transparent proxy pid=$TP_PID"

    sleep 1.5

    echo "[start.sh] Starting dashboard (foreground) ..."
    "$PYTHON" "$DASHBOARD" >>"$DASHBOARD_LOG" 2>&1 &
    DASH_PID=$!
    echo "$DASH_PID" > "$DASHBOARD_PIDFILE"
    echo "[start.sh] Dashboard pid=$DASH_PID"

    echo
    echo "[start.sh] Transparent proxy: 127.0.0.1:8444"
    echo "[start.sh] Dashboard:         http://127.0.0.1:9090"
    echo "[start.sh] Press Ctrl+C to stop both."
    echo

    cleanup() {
        echo
        echo "[start.sh] Stopping ..."
        kill "$TP_PID" 2>/dev/null || true
        kill "$DASH_PID" 2>/dev/null || true
        rm -f "$TPROXY_PIDFILE" "$DASHBOARD_PIDFILE"
        wait "$TP_PID" 2>/dev/null || true
        wait "$DASH_PID" 2>/dev/null || true
        echo "[start.sh] Stopped."
    }
    trap cleanup EXIT INT TERM

    wait
}

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

do_setup() {
    echo "[start.sh] Running one-time root setup..."
    sudo bash "$PROJECT_DIR/setup_iptables.sh"
}

# ─── main ───────────────────────────────────────────────────────────────────

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
