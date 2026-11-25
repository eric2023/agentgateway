#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
#
# One-time root setup for AgentGateway transparent proxy:
#   1. modprobe xt_cgroup
#   2. Create cgroup net_cls/agentgateway (classid 0x100001)
#   3. chmod 666 tasks (allow non-root agw-admit to write)
#   4. Install system-level CA
#   5. Set iptables-legacy REDIRECT rule
#
# Usage: sudo bash setup_iptables.sh           # setup
#        sudo bash setup_iptables.sh --cleanup  # remove iptables rule

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IPTABLES="/usr/sbin/iptables-legacy"
CGROUP_DIR="/sys/fs/cgroup/net_cls/agentgateway"
CLASSID="0x100001"
REDIRECT_PORT=8444

# ─── Cleanup mode ──────────────────────────────────────────────────────────
if [[ "${1:-}" == "--cleanup" ]]; then
    echo "[setup] Removing iptables rule..."
    $IPTABLES -t nat -D OUTPUT \
        -p tcp --dport 443 -m cgroup --cgroup "$CLASSID" \
        -j REDIRECT --to-port "$REDIRECT_PORT" 2>/dev/null || true
    echo "[setup] iptables rule removed"
    exit 0
fi

# ─── 1. Load kernel module ─────────────────────────────────────────────────
echo "[setup] Loading xt_cgroup module..."
modprobe xt_cgroup 2>/dev/null || {
    echo "[setup] WARNING: modprobe xt_cgroup failed — cgroup match may not work"
}

# ─── 2. Create cgroup ──────────────────────────────────────────────────────
echo "[setup] Creating cgroup $CGROUP_DIR..."
mkdir -p "$CGROUP_DIR"
echo "$CLASSID" > "$CGROUP_DIR/net_cls.classid"

# ─── 3. Allow non-root processes to join ───────────────────────────────────
chmod 666 "$CGROUP_DIR/tasks"
echo "[setup] cgroup tasks writable by all users"

# ─── 4. Install system-level CA ────────────────────────────────────────────
CA_SRC="$SCRIPT_DIR/certs/ca-cert.pem"
CA_DST="/etc/ssl/certs/agentgateway-ca.pem"
if [[ -f "$CA_SRC" ]]; then
    echo "[setup] Installing CA to $CA_DST..."
    cp "$CA_SRC" "$CA_DST"
    chmod 644 "$CA_DST"
    update-ca-certificates 2>/dev/null || true
    echo "[setup] System CA installed"
else
    echo "[setup] WARNING: $CA_SRC not found — run 'python3 gateway/gen_ca.py' first"
fi

# Also install to NSS DB for Chrome/Chromium
if command -v certutil &>/dev/null; then
    NSSDB="$HOME/.pki/nssdb"
    mkdir -p "$NSSDB"
    certutil -d "sql:$NSSDB" -A -t "C," -n "AgentGateway Root CA" -i "$CA_SRC" 2>/dev/null || true
    echo "[setup] NSS DB CA installed"
fi

# ─── 5. Set iptables rule ──────────────────────────────────────────────────
echo "[setup] Setting iptables-legacy REDIRECT rule..."

# Remove old rule if exists (ignore errors)
$IPTABLES -t nat -D OUTPUT \
    -p tcp --dport 443 -m cgroup --cgroup "$CLASSID" \
    -j REDIRECT --to-port "$REDIRECT_PORT" 2>/dev/null || true

# Add rule
$IPTABLES -t nat -A OUTPUT \
    -p tcp --dport 443 -m cgroup --cgroup "$CLASSID" \
    -j REDIRECT --to-port "$REDIRECT_PORT"

echo "[setup] iptables rule set: cgroup $CLASSID :443 → :$REDIRECT_PORT"
echo "[setup] ─────────────────────────────────────"
echo "[setup] Setup complete."
echo "[setup] Verify:   $IPTABLES -t nat -L OUTPUT -n"
echo "[setup] Cleanup:  sudo bash $0 --cleanup"
