#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
#
# AgentGateway trustexec — Agent wrapper that admits the process into
# the iptables net_cls cgroup for transparent proxy interception.
#
# Usage: trustexec.sh [--app <name>] [--agent-id <uuid>] <command> [args...]
#
# Sets:
#   AGENTGATEWAY_AGENT_ID     → unique per-launch agent ID
#   AGENTGATEWAY_SESSION_ID   → unique per-launch session ID
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
        --bpf)
            # Ignored: BPF mode was for 方案B (6.6 kernel), not applicable on 4.19
            shift
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "[trustexec] Unknown option: $1" >&2
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

# Set AgentGateway identity (read by transparent_proxy.py for audit attribution)
export AGENTGATEWAY_AGENT_ID="$AGENT_ID"
export AGENTGATEWAY_SESSION_ID="$SESSION_ID"
export AGENTGATEWAY_APP_NAME="$APP_NAME"

# Admit this process into the net_cls cgroup
if [[ -w "$CGROUP_TASKS" ]]; then
    echo $$ > "$CGROUP_TASKS"
else
    echo "[trustexec] WARNING: cannot write to $CGROUP_TASKS" >&2
    echo "[trustexec] Run setup_iptables.sh first to create the cgroup." >&2
fi

echo "[agentgateway] Agent ID:   $AGENT_ID"
echo "[agentgateway] Session ID: $SESSION_ID"
echo "[agentgateway] App:        $APP_NAME"
echo "[agentgateway] Cgroup:     $CGROUP_TASKS"
echo "[agentgateway] Command:    $@"
echo "[agentgateway] ─────────────────────────────────"

exec "$@"
