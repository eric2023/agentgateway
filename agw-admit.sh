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
                printf "%-8s %-16s %s\n" "PID" "进程名" "完整路径"
                printf "%-8s %-16s %s\n" "---" "------" "-------"
                # iterate
                for pid in $pids; do
                    comm="$(cat /proc/$pid/comm 2>/dev/null || echo '?')"
                    exe="$(readlink /proc/$pid/exe 2>/dev/null || echo '?')"
                    printf "%-8s %-16s %s\n" "$pid" "$comm" "$exe"
                done
            fi
            echo "[agentgateway] ═══════════════════════════════════════════"
            exit 0
            ;;
        --app)
            APP_NAME="$2"
            shift 2
            ;;
        --agent-id)
            AGENT_ID="$2"
            shift 2
            ;;
        --session-id)
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

# Admit this process into the net_cls cgroup
if [[ -w "$CGROUP_TASKS" ]]; then
    echo $$ > "$CGROUP_TASKS"
else
    echo "[agw-admit] WARNING: cannot write to $CGROUP_TASKS" >&2
    echo "[agw-admit] Run setup_iptables.sh first to create the cgroup." >&2
fi

echo "[agentgateway] Agent ID:   $AGENT_ID"
echo "[agentgateway] Session ID: $SESSION_ID"
echo "[agentgateway] App:        $APP_NAME"
echo "[agentgateway] Cgroup:     $CGROUP_TASKS"
echo "[agentgateway] Command:    $@"
echo "[agentgateway] ─────────────────────────────────"

exec "$@"
