#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
#
# One-time root setup for AgentGateway transparent proxy:
#   1. modprobe xt_cgroup
#   2. Create cgroup net_cls/agentgateway (classid 0x100001)
#   3. chmod 666 tasks (allow non-root agw-admit to write)
#   4. Install system-level CA (certs/ca-cert.pem)
#   5. Set iptables-legacy REDIRECT rules for common HTTPS ports
#
# Usage: sudo bash setup_iptables.sh           # setup
#        sudo bash setup_iptables.sh --cleanup  # remove iptables rules

set -uo pipefail
# Fix HOME when invoked via sudo without --preserve-env
if [[ -n "${SUDO_USER:-}" && "$HOME" == "/root" ]]; then
    SUDO_HOME="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -6)"
    [[ -n "$SUDO_HOME" ]] && HOME="$SUDO_HOME"
fi
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IPTABLES="/usr/sbin/iptables-legacy"
CGROUP_DIR="/sys/fs/cgroup/net_cls/agentgateway"
CLASSID="0x100001"
REDIRECT_PORT=8444
PROXY_GID=""
# Try to find the agwproxy group GID (created by setup or manually)
if getent group agwproxy &>/dev/null; then
    PROXY_GID="$(getent group agwproxy | cut -d: -f3)"
fi

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
  4. 安装 AgentGateway CA (certs/ca-cert.pem) 到系统 CA
  5. 设置 iptables-legacy REDIRECT 规则（:443 :8443 :9443 → :8444）

验证:  /usr/sbin/iptables-legacy -t nat -L OUTPUT -n
清理:  sudo bash setup_iptables.sh --cleanup
EOF
    exit 0
fi

# ─── Cleanup mode ──────────────────────────────────────────────────────────
if [[ "${1:-}" == "--cleanup" ]]; then
    if [[ "$EUID" -ne 0 ]]; then
        echo "[setup] ERROR: --cleanup 需要 root 权限，请用 sudo 运行" >&2
        echo "[setup]   sudo bash $0 --cleanup" >&2
        exit 1
    fi
    echo "[setup] Removing iptables rules..."
    removed=0
    # Get PROXY_GID for removing GID-exclusion rules
    PROXY_GID_CLEANUP=""
    if getent group agwproxy &>/dev/null; then
        PROXY_GID_CLEANUP="$(getent group agwproxy | cut -d: -f3)"
    fi
    for port in "${HTTPS_PORTS[@]}"; do
        # Remove GID-exclusion RETURN rule
        if [[ -n "$PROXY_GID_CLEANUP" ]]; then
            $IPTABLES -t nat -D OUTPUT \
                -p tcp --dport "$port" -m owner --gid-owner "$PROXY_GID_CLEANUP" \
                -j RETURN 2>/dev/null && removed=$((removed + 1))
        fi
        # Remove REDIRECT rule
        if $IPTABLES -t nat -D OUTPUT \
            -p tcp --dport "$port" -m cgroup --cgroup "$CLASSID" \
            -j REDIRECT --to-port "$REDIRECT_PORT" 2>/dev/null; then
            echo "[setup]   removed rule for :$port"
            removed=$((removed + 1))
        fi
    done
    echo "[setup] iptables rules removed: $removed (ports: ${HTTPS_PORTS[*]})"
    echo "[setup] verify: $IPTABLES -t nat -L OUTPUT -n"
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
CA_DST="/usr/local/share/ca-certificates/agentgateway-ca.crt"

# If CA doesn't exist, generate it by running the Rust binary briefly
if [[ ! -f "$CA_SRC" ]]; then
    echo "[setup] CA not found at $CA_SRC, generating via agentgateway..."
    if [[ -x "$SCRIPT_DIR/target/release/agentgateway" ]]; then
        timeout 3 "$SCRIPT_DIR/target/release/agentgateway" --port 0 2>/dev/null || true
    elif [[ -x "$SCRIPT_DIR/target/debug/agentgateway" ]]; then
        timeout 3 "$SCRIPT_DIR/target/debug/agentgateway" --port 0 2>/dev/null || true
    else
        echo "[setup] WARNING: agentgateway binary not found. Build with: cargo build --release" >&2
    fi
fi

if [[ -f "$CA_SRC" ]]; then
    echo "[setup] Installing AgentGateway CA to $CA_DST..."
    cp "$CA_SRC" "$CA_DST"
    chmod 644 "$CA_DST"
    update-ca-certificates 2>&1
    # Verify CA actually entered the system bundle; if not, force rebuild
    if ! grep -q "AgentGateway" /etc/ssl/certs/ca-certificates.crt 2>/dev/null; then
        echo "[setup] CA not in bundle after update, rebuilding with --fresh..." >&2
        update-ca-certificates --fresh 2>&1
    fi
    if grep -q "AgentGateway" /etc/ssl/certs/ca-certificates.crt 2>/dev/null; then
        echo "[setup] System CA installed and verified in ca-certificates.crt"
    else
        echo "[setup] ERROR: CA not found in /etc/ssl/certs/ca-certificates.crt!" >&2
        echo "[setup] Try manually: sudo update-ca-certificates --fresh" >&2
    fi
else
    echo "[setup] WARNING: $CA_SRC not found — CA generation failed" >&2
fi

# Also install to NSS DB for Chrome/Chromium
if command -v certutil &>/dev/null; then
    NSSDB="$HOME/.pki/nssdb"
    mkdir -p "$NSSDB"
    # Remove old mitmproxy nickname if present (migration from old setup)
    certutil -d "sql:$NSSDB" -D -n "mitmproxy" 2>/dev/null || true
    certutil -d "sql:$NSSDB" -D -n "agentgateway" 2>/dev/null || true
    if [[ -f "$CA_SRC" ]]; then
        certutil -d "sql:$NSSDB" -A -t "C,," -n "agentgateway" -i "$CA_SRC" 2>/dev/null || true
        echo "[setup] NSS DB CA installed (nickname: agentgateway)"
    fi
fi

# ─── 5. Create agwproxy group for proxy GID exclusion ─────────────────────
# The proxy process runs under the agwproxy GID so iptables can exclude its
# outgoing connections from REDIRECT (prevents proxy→self redirect loop).
if ! getent group agwproxy &>/dev/null; then
    groupadd -r agwproxy
    echo "[setup] Created system group 'agwproxy'"
fi
PROXY_GID="$(getent group agwproxy | cut -d: -f3)"
echo "[setup] Proxy GID: $PROXY_GID (agwproxy)"

# ─── 6. Set iptables rules ─────────────────────────────────────────────────
echo "[setup] Setting iptables-legacy REDIRECT rules for ports: ${HTTPS_PORTS[*]}..."

# First: remove old rules (both old format without GID exclusion and new format)
for port in "${HTTPS_PORTS[@]}"; do
    # Remove old GID-exclusion RETURN rule
    $IPTABLES -t nat -D OUTPUT \
        -p tcp --dport "$port" -m owner --gid-owner "$PROXY_GID" \
        -j RETURN 2>/dev/null || true
    # Remove old REDIRECT rule (old format, no GID exclusion)
    $IPTABLES -t nat -D OUTPUT \
        -p tcp --dport "$port" -m cgroup --cgroup "$CLASSID" \
        -j REDIRECT --to-port "$REDIRECT_PORT" 2>/dev/null || true
done

# Add new rules: GID exclusion RETURN first, then REDIRECT for cgroup traffic
for port in "${HTTPS_PORTS[@]}"; do
    # Exclude proxy's own outgoing connections (prevents redirect loop)
    $IPTABLES -t nat -A OUTPUT \
        -p tcp --dport "$port" -m owner --gid-owner "$PROXY_GID" \
        -j RETURN
    # Redirect cgroup traffic to proxy
    $IPTABLES -t nat -A OUTPUT \
        -p tcp --dport "$port" -m cgroup --cgroup "$CLASSID" \
        -j REDIRECT --to-port "$REDIRECT_PORT"
done

echo "[setup] iptables rules set: cgroup $CLASSID ports ${HTTPS_PORTS[*]} → :$REDIRECT_PORT"
echo "[setup] ─────────────────────────────────────"
echo "[setup] Setup complete."
echo "[setup] Verify:   $IPTABLES -t nat -L OUTPUT -n"
echo "[setup] Cleanup:  sudo bash $0 --cleanup"
