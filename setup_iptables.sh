#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
#
# One-time root setup for AgentGateway transparent proxy:
#   1. modprobe xt_cgroup
#   2. Create cgroup net_cls/agentgateway (classid 0x100001)
#   3. chmod 666 tasks (allow non-root agw-admit to write)
#   4. Install system-level CA
#   5. Set iptables-legacy REDIRECT rules for common HTTPS ports
#
# Usage: sudo bash setup_iptables.sh           # setup
#        sudo bash setup_iptables.sh --cleanup  # remove iptables rules

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IPTABLES="/usr/sbin/iptables-legacy"
CGROUP_DIR="/sys/fs/cgroup/net_cls/agentgateway"
CLASSID="0x100001"
REDIRECT_PORT=8444

# Common HTTPS ports used by AI API endpoints
HTTPS_PORTS=(443 8443 9443)

# ─── Help ──────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    cat <<'EOF'
AgentGateway 一次性 root 设置脚本

Usage: sudo bash setup_iptables.sh [选项]

选项:
  (无)        执行一次性设置（modprobe + cgroup + iptables + CA）
  --cleanup   移除 iptables REDIRECT 规则
  -h, --help  显示此帮助信息

执行内容:
  1. modprobe xt_cgroup — 加载 cgroup 匹配内核模块
  2. 创建 cgroup /sys/fs/cgroup/net_cls/agentgateway（classid 0x100001）
  3. chmod 666 tasks — 允许普通用户 agw-admit 写入
  4. 安装 mitmproxy CA 到 /etc/ssl/certs/agentgateway-ca.pem
  5. 设置 iptables-legacy REDIRECT 规则（:443 :8443 :9443 → :8444）

验证:  /usr/sbin/iptables-legacy -t nat -L OUTPUT -n
清理:  sudo bash setup_iptables.sh --cleanup
EOF
    exit 0
fi

# ─── Cleanup mode ──────────────────────────────────────────────────────────
if [[ "${1:-}" == "--cleanup" ]]; then
    echo "[setup] Removing iptables rules..."
    for port in "${HTTPS_PORTS[@]}"; do
        $IPTABLES -t nat -D OUTPUT \
            -p tcp --dport "$port" -m cgroup --cgroup "$CLASSID" \
            -j REDIRECT --to-port "$REDIRECT_PORT" 2>/dev/null || true
    done
    echo "[setup] iptables rules removed (ports: ${HTTPS_PORTS[*]})"
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

# ─── 4. Install system-level CA (mitmproxy CA) ─────────────────────────────
MITM_CA_DIR="$HOME/.mitmproxy"
MITM_CA_SRC="$MITM_CA_DIR/mitmproxy-ca-cert.pem"
CA_DST="/etc/ssl/certs/agentgateway-ca.pem"

# Generate mitmproxy CA on first run
if [[ ! -f "$MITM_CA_SRC" ]]; then
    echo "[setup] Generating mitmproxy CA..."
    timeout 3 mitmdump --quiet 2>/dev/null || true
fi

if [[ -f "$MITM_CA_SRC" ]]; then
    echo "[setup] Installing mitmproxy CA to $CA_DST..."
    cp "$MITM_CA_SRC" "$CA_DST"
    chmod 644 "$CA_DST"
    update-ca-certificates 2>/dev/null || true
    echo "[setup] System CA installed"
else
    echo "[setup] WARNING: $MITM_CA_SRC not found — mitmproxy CA generation failed"
fi

# Also install to NSS DB for Chrome/Chromium
if command -v certutil &>/dev/null; then
    NSSDB="$HOME/.pki/nssdb"
    mkdir -p "$NSSDB"
    certutil -d "sql:$NSSDB" -D -n "AgentGateway Root CA" 2>/dev/null || true
    certutil -d "sql:$NSSDB" -A -t "C,," -n "mitmproxy" -i "$MITM_CA_SRC" 2>/dev/null || true
    echo "[setup] NSS DB CA installed"
fi

# ─── 5. Set iptables rules ─────────────────────────────────────────────────
echo "[setup] Setting iptables-legacy REDIRECT rules for ports: ${HTTPS_PORTS[*]}..."

for port in "${HTTPS_PORTS[@]}"; do
    # Remove old rule if exists (ignore errors)
    $IPTABLES -t nat -D OUTPUT \
        -p tcp --dport "$port" -m cgroup --cgroup "$CLASSID" \
        -j REDIRECT --to-port "$REDIRECT_PORT" 2>/dev/null || true
    # Add rule
    $IPTABLES -t nat -A OUTPUT \
        -p tcp --dport "$port" -m cgroup --cgroup "$CLASSID" \
        -j REDIRECT --to-port "$REDIRECT_PORT"
done

echo "[setup] iptables rules set: cgroup $CLASSID ports ${HTTPS_PORTS[*]} → :$REDIRECT_PORT"
echo "[setup] ─────────────────────────────────────"
echo "[setup] Setup complete."
echo "[setup] Verify:   $IPTABLES -t nat -L OUTPUT -n"
echo "[setup] Cleanup:  sudo bash $0 --cleanup"
