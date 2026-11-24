#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# AgentGateway trustexec — Agent wrapper that injects proxy + CA trust + LD_PRELOAD.
#
# Usage: trustexec.sh [--app <name>] [--agent-id <uuid>] <command> [args...]
#
# Sets:
#   SSL_CERT_FILE             → AgentGateway CA cert (for OpenSSL/Qt apps)
#   NODE_EXTRA_CA_CERTS       → AgentGateway CA cert (for Electron/Node apps)
#   REQUESTS_CA_BUNDLE        → AgentGateway CA cert (for Python requests)
#   PI_PROXY                  → AgentGateway proxy (for omp/Bun fetch wrapper)
#   AGENTGATEWAY_AGENT_ID     → unique per-launch agent ID
#   AGENTGATEWAY_SESSION_ID   → unique per-launch session ID
#   LD_PRELOAD                → libauditshim.so (if built)
#
# All zero-modification to the wrapped application.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"
SHIM_PATH="$SCRIPT_DIR/gateway/libauditshim.so"
GATEWAY_HOST="127.0.0.1"
GATEWAY_PORT="8443"

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
        --)
            shift
            break
            ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

if [[ $# -eq 0 ]]; then
    echo "Usage: trustexec.sh [--app <name>] [--agent-id <uuid>] <command> [args...]"
    exit 1
fi

# Generate IDs if not provided
if [[ -z "$AGENT_ID" ]]; then
    AGENT_ID="agent-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4().hex[:8])')"
fi
if [[ -z "$SESSION_ID" ]]; then
    SESSION_ID="session-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4().hex[:8])')"
fi

# Set proxy environment
export HTTPS_PROXY="http://${GATEWAY_HOST}:${GATEWAY_PORT}"
export HTTP_PROXY="http://${GATEWAY_HOST}:${GATEWAY_PORT}"
export https_proxy="http://${GATEWAY_HOST}:${GATEWAY_PORT}"
export http_proxy="http://${GATEWAY_HOST}:${GATEWAY_PORT}"
export NO_PROXY="localhost,127.0.0.1"
export no_proxy="localhost,127.0.0.1"

# omp (Bun-based): PI_PROXY is omp's own proxy var. Without it, omp's global
# fetch wrapper is not installed and HTTPS_PROXY is ignored for fetch calls.
# PI_PROXY_<PROVIDER> overrides per-provider; PI_PROXY is the global default.
export PI_PROXY="http://${GATEWAY_HOST}:${GATEWAY_PORT}"

# Node.js compat layer: enable env proxy for http.Agent (used by some libs)
export NODE_USE_ENV_PROXY=1

# Unset PAC/auto-proxy vars — they make Node/undici use a PAC file instead
# of HTTPS_PROXY, bypassing the gateway entirely.
unset auto_proxy

# Set CA trust
export SSL_CERT_FILE="$CERTS_DIR/ca-cert.pem"
export REQUESTS_CA_BUNDLE="$CERTS_DIR/ca-cert.pem"
export NODE_EXTRA_CA_CERTS="$CERTS_DIR/ca-cert.pem"

# Set AgentGateway identity
export AGENTGATEWAY_AGENT_ID="$AGENT_ID"
export AGENTGATEWAY_SESSION_ID="$SESSION_ID"
export AGENTGATEWAY_APP_NAME="$APP_NAME"
# System proxy (gsettings) management is now handled by the gateway daemon
# itself (agentgatewayd.py: gw_proxy_setup/gw_proxy_restore).  Previously
# trustexec.sh set gsettings to 'manual' and restored on exit, but daemon
# processes (hermes, uos-ai-assistant) outlive trustexec, causing the proxy
# to be restored while the daemon was still running.  The gateway process
# owns the lifecycle: gsettings stays 'manual' while the gateway is alive
# and is restored on shutdown.
# Kill any existing persistent daemon for the target command.
# Apps like omp spawn a background daemon that inherits the parent's env.
# If an old daemon is running without proxy env vars, it will handle API
# calls and bypass the gateway. Kill it so the new instance spawns a fresh
# daemon with the correct env.
CMD_BASENAME=$(basename "$1" 2>/dev/null)
if [[ "$CMD_BASENAME" == "omp" ]]; then
    pkill -f "omp __omp_worker_daemon" 2>/dev/null || true
    sleep 1
    echo "[agentgateway] Killed existing omp daemon"
fi

# Bun/Node: allow our MITM CA cert (NODE_EXTRA_CA_CERTS is already set).
# Don't disable TLS verification — the CA cert is trusted instead.
unset NODE_TLS_REJECT_UNAUTHORIZED

# Set LD_PRELOAD if shim exists
if [[ -f "$SHIM_PATH" ]]; then
    if [[ -n "$LD_PRELOAD" ]]; then
        export LD_PRELOAD="$SHIM_PATH:$LD_PRELOAD"
    else
        export LD_PRELOAD="$SHIM_PATH"
    fi
fi

echo "[agentgateway] Agent ID:   $AGENT_ID"
echo "[agentgateway] Session ID: $SESSION_ID"
echo "[agentgateway] App:        $APP_NAME"
echo "[agentgateway] Proxy:      $HTTPS_PROXY"
echo "[agentgateway] CA cert:    $SSL_CERT_FILE"
echo "[agentgateway] Command:    $@"
echo "[agentgateway] LD_PRELOAD: ${LD_PRELOAD:-none}"
echo "[agentgateway] ─────────────────────────────────"

# Execute the wrapped command.  The gateway daemon manages gsettings, so
# there is no trap to fire — we can use exec directly.
exec "$@"
