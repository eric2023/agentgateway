#!/bin/bash
# start.sh — Start AgentGateway (Rust transparent proxy) + Dashboard.
#
# Usage:
#   ./start.sh start      # start Rust proxy + dashboard (background)
#   ./start.sh -d         # same as start (daemon mode)
#   ./start.sh fg         # start in foreground (Ctrl+C to stop both)
#   ./start.sh stop       # stop both
#   ./start.sh restart    # restart both
#   ./start.sh status     # show running status
#   ./start.sh setup      # one-time root setup (iptables + cgroup + CA)

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
DASHBOARD="$PROJECT_DIR/dashboard/dashboard.py"
LOG_DIR="$PROJECT_DIR/logs"
PROXY_LOG="$LOG_DIR/proxy.log"
DASHBOARD_LOG="$LOG_DIR/dashboard.log"
PROXY_PIDFILE="$LOG_DIR/proxy.pid"
DASHBOARD_PIDFILE="$LOG_DIR/dashboard.pid"
BPF_LSM_PIDFILE="$LOG_DIR/bpf_lsm.pid"
BPF_LSM_LOG="$LOG_DIR/bpf_lsm.log"
AUDIT_CONSUMER_PIDFILE="$LOG_DIR/audit_consumer.pid"
AUDIT_CONSUMER_LOG="$LOG_DIR/audit_consumer.log"
PYTHON="$(command -v python3 || true)"
if [[ -z "$PYTHON" ]]; then
    PYTHON="/home/ut000520@uos/.pyenv/shims/python3"
fi
PROXY_BIN="$PROJECT_DIR/target/release/agentgateway"
PROXY_PORT=8444

mkdir -p "$LOG_DIR"

# ─── platform detection ────────────────────────────────────────────────────
# V25: cgroup v2 unified (/sys/fs/cgroup is cgroup2fs) → nftables + BPF-LSM
# V20: cgroup v1 net_cls (/sys/fs/cgroup/net_cls/) → iptables-legacy
is_cgroup_v2() {
    [[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" == "cgroup2fs" ]]
}
is_v25() { is_cgroup_v2; }
# ─── helpers ────────────────────────────────────────────────────────────────

# sudo wrapper: use AGW_SUDO_PASS env var (sudo -S) if set, else plain sudo
agw_sudo() {
    if [[ -n "${AGW_SUDO_PASS:-}" ]]; then
        printf '%s\n' "$AGW_SUDO_PASS" | sudo -S -p '' "$@"
    else
        sudo "$@"
    fi
}

# Wait for a TCP port to become connectable (replaces fixed sleep, C20)
wait_for_port() {
    local port=$1 timeout=$2
    for _ in $(seq 1 "$timeout"); do
        if timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

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
stop_proc_root() {
    local name="$1" pidfile="$2"
    local pid
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && agw_sudo kill -0 "$pid" 2>/dev/null; then
        echo "[start.sh] Stopping $name (pid=$pid) ..."
        agw_sudo kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 10); do
            agw_sudo kill -0 "$pid" 2>/dev/null || break
            sleep 0.3
        done
        agw_sudo kill -0 "$pid" 2>/dev/null && agw_sudo kill -9 "$pid" 2>/dev/null || true
        echo "[start.sh] $name stopped."
    else
        echo "[start.sh] $name not running."
    fi
    rm -f "$pidfile"
}

# Kill any stale process listening on the proxy or dashboard port.
# Handles cases where ss can't show PID (e.g. process under sg/root).
# Searches /proc/*/fd for the socket inode.
kill_stale_proc_on_port() {
    local port=$1 label=$2
    # Convert port to hex for /proc/net/tcp (little-endian)
    local hex_port
    hex_port=$(printf '%04X' "$port")
    # Get all socket inodes listening on this port
    local inodes
    inodes=$(awk -v p=":$hex_port " '$2 ~ p && $4=="0A" {print $10}' /proc/net/tcp 2>/dev/null)
    if [[ -z "$inodes" ]]; then
        return 0
    fi
    local pids=""
    for inode in $inodes; do
        for f in /proc/[0-9]*/fd/*; do
            if [[ "$(readlink "$f" 2>/dev/null)" == "socket:[$inode]" ]]; then
                local pid
                pid=$(echo "$f" | grep -oP '/proc/\K[0-9]+')
                pids="$pids $pid"
                break
            fi
        done 2>/dev/null
    done
    pids=$(echo "$pids" | tr ' ' '\n' | sort -u | grep -v '^$')
    if [[ -n "$pids" ]]; then
        echo "[start.sh] Killing stale $label on port $port (pid=$(echo $pids | tr '\n' ' ')) ..."
        for p in $pids; do
            kill "$p" 2>/dev/null || true
        done
        sleep 1
        for p in $pids; do
            kill -9 "$p" 2>/dev/null || true
        done
        sleep 0.5
    fi
}

kill_stale_proxy() {
    kill_stale_proc_on_port "$PROXY_PORT" "proxy"
    kill_stale_proc_on_port 9090 "dashboard"
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
    # Use release binary if available, fall back to debug
    local bin
    if [[ -x "$PROXY_BIN" ]]; then
        bin="$PROXY_BIN"
    elif [[ -x "$PROJECT_DIR/target/debug/agentgateway" ]]; then
        bin="$PROJECT_DIR/target/debug/agentgateway"
    else
        echo "[start.sh] ERROR: agentgateway binary not found. Build with: cargo build --release" >&2
        exit 1
    fi
    # Run as the current user (no sg agwproxy). The iptables REDIRECT rule only
    # matches cgroup members (classid 0x100001), and the proxy is NOT in that
    # cgroup, so its upstream connections are never redirected. Using sg agwproxy
    # changes the effective GID, which breaks readlink on /proc/<pid>/fd/*
    # (ptrace_may_access checks gid equality), making process attribution fail.
    echo "ulimit -n 65536; $bin --host 127.0.0.1 --port $PROXY_PORT"
}

# ─── actions ────────────────────────────────────────────────────────────────

do_stop() {
    stop_proc "proxy" "$PROXY_PIDFILE"
    stop_proc "dashboard" "$DASHBOARD_PIDFILE"
    # V25-only: stop audit consumer (root) and BPF-LSM loader (root)
    if is_v25; then
        stop_proc_root "audit_consumer" "$AUDIT_CONSUMER_PIDFILE"
        # BPF-LSM runs under strace wrapper; kill both strace and agent_lsm
        stop_proc_root "bpf_lsm(strace)" "$BPF_LSM_PIDFILE"
        agw_sudo pkill -TERM -x strace 2>/dev/null || true
        agw_sudo pkill -TERM -x agent_lsm 2>/dev/null || true
        sleep 1
        agw_sudo pkill -KILL -x strace 2>/dev/null || true
        agw_sudo pkill -KILL -x agent_lsm 2>/dev/null || true
        # Clean up pinned BPF maps so the next start doesn't hit stale pins
        agw_sudo rm -rf /sys/fs/bpf/agentgateway 2>/dev/null || true
    fi
}
do_start() {
    # Stop existing proxy/dashboard first (clean restart).
    stop_proc "proxy" "$PROXY_PIDFILE" 2>/dev/null || true
    stop_proc "dashboard" "$DASHBOARD_PIDFILE" 2>/dev/null || true
    kill_stale_proxy

    # Health checks: verify CA + cgroup are ready (platform-specific)
    if [[ ! -f /usr/local/share/ca-certificates/agentgateway-ca.crt ]]; then
        echo "[start.sh] WARNING: System CA not installed. Run './start.sh setup' first."
    fi
    if is_v25; then
        if [[ ! -d /sys/fs/cgroup/agentgateway/agents ]]; then
            echo "[start.sh] WARNING: cgroup v2 subtree not ready. Run './start.sh setup' first."
        fi
        if ! agw_sudo iptables-legacy -t nat -L OUTPUT 2>/dev/null | grep -q agentgateway; then
            echo "[start.sh] WARNING: iptables-legacy cgroup v2 redirect rules not found. Run './start.sh setup' first."
        fi
    else
        if [[ ! -w /sys/fs/cgroup/net_cls/agentgateway/tasks ]]; then
            echo "[start.sh] WARNING: cgroup not ready. Run './start.sh setup' first."
        fi
    fi

    # V25: start BPF-LSM loader (root) via systemd-run transient service.
    # Using systemd-run avoids nohup/disown issues and properly daemonizes
    # the process. BPF maps auto-detach on process death, and the loader
    # unpins stale pins before re-pinning (so no cleanup needed here).
    if is_v25; then
        if ! agw_sudo kill -0 "$(cat "$BPF_LSM_PIDFILE" 2>/dev/null)" 2>/dev/null; then
            LSM_BIN="$PROJECT_DIR/bpf/agent_lsm"
            if [[ -x "$LSM_BIN" ]]; then
                # Workaround: on this UOS 6.6 kernel, a background BPF-LSM
                # loader loses its BPF map fds after pinning (likely a DDE
                # security module interference). Running under strace (ptrace)
                # prevents the fd closure. strace -f follows forks, -o /dev/null
                # discards trace output.
                local strace_bin=""
                command -v strace &>/dev/null && strace_bin="strace"
                if [[ -n "$strace_bin" ]]; then
                    echo "[start.sh] Starting BPF-LSM loader (root, strace-wrapped)..."
                    agw_sudo bash -c "cd '$PROJECT_DIR' && AGW_ENFORCE_FILE_WRITE='${AGW_ENFORCE_FILE_WRITE:-0}' strace -f -o /tmp/agw_bpf_strace.log '$LSM_BIN' < /dev/null > '$BPF_LSM_LOG' 2>&1 & disown; echo \$! > '$BPF_LSM_PIDFILE'"
                else
                    echo "[start.sh] Starting BPF-LSM loader (root)..."
                    agw_sudo bash -c "cd '$PROJECT_DIR' && AGW_ENFORCE_FILE_WRITE='${AGW_ENFORCE_FILE_WRITE:-0}' nohup '$LSM_BIN' > '$BPF_LSM_LOG' 2>&1 & disown; echo \$! > '$BPF_LSM_PIDFILE'"
                fi
                # Wait briefly for maps to be pinned (bpffs requires root to traverse)
                for _ in $(seq 1 20); do
                    agw_sudo test -f /sys/fs/bpf/agentgateway/audit_buf 2>/dev/null && break
                    sleep 0.5
                done
            else
                echo "[start.sh] WARNING: BPF-LSM binary not found at $LSM_BIN (build with: cd bpf && make)" >&2
            fi
        else
            echo "[start.sh] BPF-LSM loader already running (pid=$(cat "$BPF_LSM_PIDFILE"))"
        fi
    fi

    start_proc "proxy" "$(proxy_cmd)" "$PROXY_PIDFILE" "$PROXY_LOG"
    # Wait for proxy port to be ready (replaces fixed sleep, C20)
    wait_for_port "$PROXY_PORT" 50 || echo "[start.sh] WARNING: proxy port not ready yet"
    start_proc "dashboard" "$PYTHON $DASHBOARD" "$DASHBOARD_PIDFILE" "$DASHBOARD_LOG"

    # V25: start audit consumer (BPF ring buffer → SQLite). Must run as root
    # because bpffs (BPF filesystem) ignores Unix file permissions and requires
    # CAP_SYS_ADMIN to open pinned maps, even with setcap.
    if is_v25; then
        if agw_sudo test -f /sys/fs/bpf/agentgateway/audit_buf 2>/dev/null; then
            echo "[start.sh] Starting BPF audit consumer → SQLite (root)..."
            agw_sudo bash -c "nohup '$PROJECT_DIR/bpf/audit_consumer' --sqlite '$PROJECT_DIR/audit/audit.db' > '$AUDIT_CONSUMER_LOG' 2>&1 & disown; echo \$! > '$AUDIT_CONSUMER_PIDFILE'"
        else
            echo "[start.sh] NOTE: BPF audit_buf not pinned (BPF-LSM not loaded?) — audit_consumer skipped" >&2
        fi
    fi

    echo
    echo "[start.sh] ─────────────────────────────────────"
    echo "[start.sh] proxy (transparent): 127.0.0.1:$PROXY_PORT"
    echo "[start.sh] Dashboard:               http://127.0.0.1:9090"
    echo "[start.sh] Logs:  $PROXY_LOG"
    echo "[start.sh]        $DASHBOARD_LOG"
    echo "[start.sh] Stop:  $0 stop"
    echo "[start.sh] ─────────────────────────────────────"
}

do_foreground() {
    # Stop any background instances.
    do_stop 2>/dev/null || true
    kill_stale_proxy

    echo "[start.sh] Starting proxy (foreground) ..."
    bash -c "$(proxy_cmd)" >>"$PROXY_LOG" 2>&1 &
    PROXY_PID=$!
    echo "$PROXY_PID" > "$PROXY_PIDFILE"
    echo "[start.sh] proxy pid=$PROXY_PID"

    wait_for_port "$PROXY_PORT" 50 || echo "[start.sh] WARNING: proxy port not ready yet"

    echo "[start.sh] Starting dashboard (foreground) ..."
    "$PYTHON" "$DASHBOARD" >>"$DASHBOARD_LOG" 2>&1 &
    DASH_PID=$!
    echo "$DASH_PID" > "$DASHBOARD_PIDFILE"
    echo "[start.sh] Dashboard pid=$DASH_PID"

    echo
    echo "[start.sh] proxy (transparent): 127.0.0.1:$PROXY_PORT"
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
        echo "[start.sh] proxy: running (pid=$(cat "$PROXY_PIDFILE"))"
    else
        echo "[start.sh] proxy: stopped"
    fi
    if is_running "$DASHBOARD_PIDFILE"; then
        echo "[start.sh] Dashboard: running (pid=$(cat "$DASHBOARD_PIDFILE"))"
    else
        echo "[start.sh] Dashboard: stopped"
    fi
    if is_v25; then
        if agw_sudo kill -0 "$(cat "$BPF_LSM_PIDFILE" 2>/dev/null)" 2>/dev/null; then
            echo "[start.sh] BPF-LSM: running (pid=$(cat "$BPF_LSM_PIDFILE"))"
        else
            echo "[start.sh] BPF-LSM: stopped"
        fi
        if agw_sudo kill -0 "$(cat "$AUDIT_CONSUMER_PIDFILE" 2>/dev/null)" 2>/dev/null; then
            echo "[start.sh] audit_consumer: running (pid=$(cat "$AUDIT_CONSUMER_PIDFILE"))"
        else
            echo "[start.sh] audit_consumer: stopped"
        fi
    fi
}

do_setup() {
    echo "[start.sh] Running one-time root setup..."
    if is_v25; then
        echo "[start.sh] Detected V25 (cgroup v2) — using setup_v25.sh + BPF-LSM"
        agw_sudo bash -c "export HOME='$HOME'; '$PROJECT_DIR/setup_v25.sh' --bpf"
    else
        echo "[start.sh] Detected V20 (cgroup v1 net_cls) — using setup_iptables.sh"
        agw_sudo bash -c "export HOME='$HOME'; '$PROJECT_DIR/setup_iptables.sh'"
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
    setup)   do_setup ;;
    -h|--help|"")
        cat <<'EOF'
AgentGateway 生命周期管理脚本

Usage: ./start.sh {start|stop|restart|status|fg|setup}

命令:
  start     启动 proxy + dashboard（后台，默认）
  -d        同 start（daemon 模式）
  fg        前台运行（Ctrl+C 停止两者）
  stop      停止 proxy + dashboard
  restart   重启两者
  status    查看运行状态
  setup     一次性 root 设置（iptables + cgroup + CA）
  -h, --help  显示此帮助信息

端口:
  proxy (transparent):  127.0.0.1:8444
  Dashboard:                http://127.0.0.1:9090
EOF
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|fg|setup|-h}"
        echo "  Run '$0 -h' for full help."
        exit 1
        ;;
esac
