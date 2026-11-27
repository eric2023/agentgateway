#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
#
# AgentGateway agw-admit — Agent wrapper that admits the process into
# the iptables net_cls cgroup for transparent proxy interception.
#
# Usage: agw-admit.sh [--app <name>] [--agent-id <uuid>] <command> [args...]
#
# Sets:
#   AGENTGATEWAY_APP_NAME    → application name (for audit attribution)
#   AGENTGATEWAY_AGENT_ID    → unique per-launch agent ID
#   AGENTGATEWAY_SESSION_ID  → unique per-launch session ID
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
        -h|--help)
            cat <<'EOF'
AgentGateway agw-admit — 将进程纳入 cgroup 拦截的 Agent 包装器

Usage: agw-admit.sh [选项] [--app <名称>] <command> [args...]

选项:
  --list             查看 cgroup 信息（名称、classid、已纳入的进程）
  --app <名称>       应用名称（用于审计归属，默认 "unknown"）
  --agent-id <uuid>  Agent ID（不指定则自动生成）
  --session-id <uuid> 会话 ID（不指定则自动生成）
  -h, --help         显示此帮助信息
  --                 结束选项解析，后续参数作为命令执行

示例:
  agw-admit.sh --list
  agw-admit.sh --app "OMP" /home/ut000520@uos/.local/bin/omp
  agw-admit.sh --app "TestApp" curl -sS https://httpbin.org/get
  agw-admit.sh --app "MyAgent" python3 my_agent.py

说明:
  将当前进程写入 cgroup net_cls/agentgateway/tasks，使其 :443/:8443/:9443
  出向流量被 iptables REDIRECT 到 mitmproxy :8444 透明代理。
  Agent 零改造，无需设置任何环境变量。
EOF
            exit 0
            ;;
        --list)
            CGROUP_DIR="/sys/fs/cgroup/net_cls/agentgateway"
            echo "[agentgateway] ═══════════════════════════════════════════"
            echo "[agentgateway] Cgroup 信息"
            echo "[agentgateway] ═══════════════════════════════════════════"
            echo "[agentgateway] 路径:       $CGROUP_DIR"
            if [[ ! -d "$CGROUP_DIR" ]]; then
                echo "[agentgateway] 状态:       未创建（请先运行 ./start.sh setup）"
                exit 0
            fi
            echo "[agentgateway] 名称:       agentgateway"
            classid="$(cat "$CGROUP_DIR/net_cls.classid" 2>/dev/null || echo 'N/A')"
            echo "[agentgateway] ClassID:    $classid"
            echo "[agentgateway] tasks 权限: $(stat -c '%a' "$CGROUP_DIR/tasks" 2>/dev/null || echo 'N/A')"
            echo ""
            echo "[agentgateway] ── 已纳入的进程 ──"
            pids="$(cat "$CGROUP_DIR/tasks" 2>/dev/null)"
            if [[ -z "$pids" ]]; then
                echo "[agentgateway]   （无）"
            else
                printf "%-8s %-20s %s\n" "PID" "进程名" "完整路径"
                printf "%-8s %-20s %s\n" "---" "------" "-------"
                # iterate, deduplicate by Tgid (show main thread only)
                seen_tgids=""
                for pid in $pids; do
                    tgid="$(awk '/^Tgid:/{print $2}' /proc/$pid/status 2>/dev/null)"
                    [[ -z "$tgid" ]] && tgid="$pid"
                    # skip if this tgid was already seen (sub-thread of same process)
                    case " $seen_tgids " in
                        *" $tgid "*) continue ;;
                    esac
                    seen_tgids="$seen_tgids $tgid"
                    comm="$(cat /proc/$tgid/comm 2>/dev/null || echo '?')"
                    exe="$(readlink /proc/$tgid/exe 2>/dev/null || echo '?')"
                    printf "%-8s %-20s %s\n" "$tgid" "$comm" "$exe"
                done
            fi
            echo "[agentgateway] ═══════════════════════════════════════════"
            exit 0
            ;;
        --app)
            [[ -z "${2:-}" ]] && { echo "[agw-admit] Error: --app requires a value" >&2; exit 1; }
            APP_NAME="$2"
            shift 2
            ;;
        --agent-id)
            [[ -z "${2:-}" ]] && { echo "[agw-admit] Error: --agent-id requires a value" >&2; exit 1; }
            AGENT_ID="$2"
            shift 2
            ;;
        --session-id)
            [[ -z "${2:-}" ]] && { echo "[agw-admit] Error: --session-id requires a value" >&2; exit 1; }
            SESSION_ID="$2"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "[agw-admit] Unknown option: $1" >&2
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

# Set AgentGateway identity (read by agw_addon.py for audit attribution)
export AGENTGATEWAY_APP_NAME="$APP_NAME"
export AGENTGATEWAY_AGENT_ID="$AGENT_ID"
export AGENTGATEWAY_SESSION_ID="$SESSION_ID"

# ─── Admit into cgroup ─────────────────────────────────────────────────────
# Detect cgroup version: V25 uses cgroup v2 unified (/sys/fs/cgroup is cgroup2fs),
# V20 uses cgroup v1 net_cls (/sys/fs/cgroup/net_cls/).
CGROUP_V2_ROOT="/sys/fs/cgroup"
CGROUP_V2_AGW="$CGROUP_V2_ROOT/agentgateway/agents"
AGW_DIR="$(cd "$(dirname "$0")" && pwd)"
ADMitted="no"

if [[ "$(stat -fc %T "$CGROUP_V2_ROOT" 2>/dev/null)" == "cgroup2fs" ]]; then
    # ── V25: cgroup v2 unified ──
    # Create a per-agent cgroup under /sys/fs/cgroup/agentgateway/agents/<agent-id>/
    # and move this process into it. The BPF-LSM identity_map is keyed by cgroup
    # id, populated by bpf/agent_admit (which needs root — run via sudo if the
    # BPF-LSM loader is active). The nftables rule matches cgroupv2 level 1
    # "agentgateway" so any process in this subtree gets redirected.
    AGENT_CG="$CGROUP_V2_AGW/$AGENT_ID"
    # cgroup v2: writing cgroup.procs requires root (CAP_SYS_ADMIN) when moving
    # across cgroup hierarchies (current process is under user.slice, target is
    # under agentgateway/). The agent_admit helper writes identity_map AND moves
    # the PID into the cgroup in one root call. Both need sudo.
    ADMIT_BIN="$AGW_DIR/bpf/agent_admit"
    # sudo helper: use AGW_SUDO_PASS env var (sudo -S) if set, else sudo -n (cached)
    agw_sudo() {
        if [[ -n "${AGW_SUDO_PASS:-}" ]]; then
            printf '%s\n' "$AGW_SUDO_PASS" | sudo -S -p '' "$@"
        else
            sudo -n "$@"
        fi
    }
    agw_sudo_ok() {
        if [[ -n "${AGW_SUDO_PASS:-}" ]]; then
            printf '%s\n' "$AGW_SUDO_PASS" | sudo -S -p '' true 2>/dev/null
        else
            sudo -n true 2>/dev/null
        fi
    }
    if mkdir -p "$AGENT_CG" 2>/dev/null; then
        if [[ -x "$ADMIT_BIN" ]] && agw_sudo_ok; then
            # agent_admit: <name> <agent-id> <session-id> <app> [pid...]
            # It creates the cgroup, writes identity_map, and moves the PID.
            agw_sudo "$ADMIT_BIN" "$AGENT_ID" "$AGENT_ID" "$SESSION_ID" "$APP_NAME" $$ 2>/dev/null \
                && echo "[agw-admit] BPF-LSM identity registered + cgroup joined" \
                || echo "[agw-admit] WARNING: agent_admit failed (run agent_lsm loader?)" >&2
            ADMitted="yes"
            CGROUP_DESC="$AGENT_CG (cgroup v2 + BPF-LSM)"
        elif agw_sudo_ok; then
            agw_sudo bash -c "echo $$ > '$AGENT_CG/cgroup.procs'" 2>/dev/null \
                && ADMitted="yes" \
                || echo "[agw-admit] WARNING: cannot write cgroup.procs" >&2
            CGROUP_DESC="$AGENT_CG (cgroup v2, no BPF-LSM identity)"
        else
            echo "[agw-admit] NOTE: sudo required for cgroup v2 join + BPF-LSM identity" >&2
            echo "[agw-admit] Without sudo, traffic will NOT be redirected (nftables matches cgroup)" >&2
            echo "[agw-admit] Set AGW_SUDO_PASS or run: sudo -v" >&2
            CGROUP_DESC="$AGENT_CG (cgroup v2, needs sudo)"
        fi
    else
        echo "[agw-admit] WARNING: cannot create $AGENT_CG" >&2
        echo "[agw-admit] Run setup_v25.sh first to create the cgroup subtree." >&2
        CGROUP_DESC="(none)"
    fi
elif [[ -w "$CGROUP_TASKS" ]]; then
    # ── V20: cgroup v1 net_cls ──
    echo $$ > "$CGROUP_TASKS"
    ADMitted="yes"
    CGROUP_DESC="$CGROUP_TASKS (cgroup v1 net_cls)"
else
    echo "[agw-admit] WARNING: cannot admit into any cgroup" >&2
    echo "[agw-admit] V20: run setup_iptables.sh;  V25: run setup_v25.sh" >&2
    CGROUP_DESC="(none)"
fi
echo "[agentgateway] Agent ID:   $AGENT_ID"
echo "[agentgateway] Session ID: $SESSION_ID"
echo "[agentgateway] App:        $APP_NAME"
echo "[agentgateway] Cgroup:     $CGROUP_DESC"
echo "[agentgateway] Admitted:   $ADMitted"
echo "[agentgateway] Command:    $@"
echo "[agentgateway] ─────────────────────────────────"

exec "$@"
