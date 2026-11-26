#!/bin/bash
# start.sh — Start AgentGateway (mitmproxy transparent proxy) + Dashboard.
#
# Usage:
#   ./start.sh start      # start mitmproxy + dashboard (background)
#   ./start.sh -d         # same as start (daemon mode)
#   ./start.sh fg         # start in foreground (Ctrl+C to stop both)
#   ./start.sh stop       # stop both
#   ./start.sh restart    # restart both
#   ./start.sh status     # show running status
#   ./start.sh setup      # one-time root setup (iptables + cgroup + CA)

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
ADDON="$PROJECT_DIR/gateway/agw_addon.py"
DASHBOARD="$PROJECT_DIR/dashboard/dashboard.py"
LOG_DIR="$PROJECT_DIR/logs"
PROXY_LOG="$LOG_DIR/proxy.log"
DASHBOARD_LOG="$LOG_DIR/dashboard.log"
PROXY_PIDFILE="$LOG_DIR/proxy.pid"
DASHBOARD_PIDFILE="$LOG_DIR/dashboard.pid"

PYTHON="$(command -v python3 || true)"
if [[ -z "$PYTHON" ]]; then
    PYTHON="/home/ut000520@uos/.pyenv/shims/python3"
fi
MITMDUMP="$(command -v mitmdump || true)"
PROXY_PORT=8444

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

# start_proc accepts a full command string (supports args).
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

# ─── proxy command ──────────────────────────────────────────────────────────

proxy_cmd() {
    if [[ -z "$MITMDUMP" ]]; then
        echo "[start.sh] ERROR: mitmdump not found. Install with: pip3 install mitmproxy==5.3.0" >&2
        exit 1
    fi
    echo "$MITMDUMP --mode transparent --listen-host 127.0.0.1 --listen-port $PROXY_PORT --set ssl_insecure=true -s $ADDON"
}

# ─── actions ────────────────────────────────────────────────────────────────

do_stop() {
    stop_proc "mitmproxy" "$PROXY_PIDFILE"
    stop_proc "dashboard" "$DASHBOARD_PIDFILE"
}

do_start() {
    # Stop existing instances first (clean restart).
    do_stop 2>/dev/null || true

    # Health checks: verify iptables rule and CA are installed
    if [[ ! -f /usr/local/share/ca-certificates/agentgateway-ca.crt ]]; then
        echo "[start.sh] WARNING: System CA not installed. Run './start.sh setup' first."
    fi
    if [[ ! -w /sys/fs/cgroup/net_cls/agentgateway/tasks ]]; then
        echo "[start.sh] WARNING: cgroup not ready. Run './start.sh setup' first."
    fi

    start_proc "mitmproxy" "$(proxy_cmd)" "$PROXY_PIDFILE" "$PROXY_LOG"
    sleep 1.5   # let mitmproxy bind the port before dashboard
    start_proc "dashboard" "$PYTHON $DASHBOARD" "$DASHBOARD_PIDFILE" "$DASHBOARD_LOG"

    echo
    echo "[start.sh] ─────────────────────────────────────"
    echo "[start.sh] mitmproxy (transparent): 127.0.0.1:$PROXY_PORT"
    echo "[start.sh] Dashboard:               http://127.0.0.1:9090"
    echo "[start.sh] Logs:  $PROXY_LOG"
    echo "[start.sh]        $DASHBOARD_LOG"
    echo "[start.sh] Stop:  $0 stop"
    echo "[start.sh] ─────────────────────────────────────"
}

do_foreground() {
    # Stop any background instances.
    do_stop 2>/dev/null || true

    echo "[start.sh] Starting mitmproxy (foreground) ..."
    bash -c "$(proxy_cmd)" >>"$PROXY_LOG" 2>&1 &
    PROXY_PID=$!
    echo "$PROXY_PID" > "$PROXY_PIDFILE"
    echo "[start.sh] mitmproxy pid=$PROXY_PID"

    sleep 1.5

    echo "[start.sh] Starting dashboard (foreground) ..."
    "$PYTHON" "$DASHBOARD" >>"$DASHBOARD_LOG" 2>&1 &
    DASH_PID=$!
    echo "$DASH_PID" > "$DASHBOARD_PIDFILE"
    echo "[start.sh] Dashboard pid=$DASH_PID"

    echo
    echo "[start.sh] mitmproxy (transparent): 127.0.0.1:$PROXY_PORT"
    echo "[start.sh] Dashboard:               http://127.0.0.1:9090"
    echo "[start.sh] Press Ctrl+C to stop both."
    echo

    cleanup() {
        echo
        echo "[start.sh] Stopping ..."
        kill "$PROXY_PID" 2>/dev/null || true
        kill "$DASH_PID" 2>/dev/null || true
        rm -f "$PROXY_PIDFILE" "$DASHBOARD_PIDFILE"
        wait "$PROXY_PID" 2>/dev/null || true
        wait "$DASH_PID" 2>/dev/null || true
        echo "[start.sh] Stopped."
    }
    trap cleanup EXIT INT TERM

    wait
}

do_status() {
    if is_running "$PROXY_PIDFILE"; then
        echo "[start.sh] mitmproxy: running (pid=$(cat "$PROXY_PIDFILE"))"
    else
        echo "[start.sh] mitmproxy: stopped"
    fi
    if is_running "$DASHBOARD_PIDFILE"; then
        echo "[start.sh] Dashboard: running (pid=$(cat "$DASHBOARD_PIDFILE"))"
    else
        echo "[start.sh] Dashboard: stopped"
    fi
}

do_setup() {
    echo "[start.sh] Running one-time root setup..."
    sudo --preserve-env=HOME bash "$PROJECT_DIR/setup_iptables.sh"
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
    -h|--help|"")
        cat <<'EOF'
AgentGateway 生命周期管理脚本

Usage: ./start.sh {start|stop|restart|status|fg|setup}

命令:
  start     启动 mitmproxy + dashboard（后台，默认）
  -d        同 start（daemon 模式）
  fg        前台运行（Ctrl+C 停止两者）
  stop      停止 mitmproxy + dashboard
  restart   重启两者
  status    查看运行状态
  setup     一次性 root 设置（iptables + cgroup + CA）
  -h, --help  显示此帮助信息

端口:
  mitmproxy (transparent):  127.0.0.1:8444
  Dashboard:                http://127.0.0.1:9090
EOF
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|fg|setup|-h}"
        echo "  Run '$0 -h' for full help."
        exit 1
        ;;
esac
