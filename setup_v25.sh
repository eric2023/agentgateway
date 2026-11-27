#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
#
# One-time root setup for AgentGateway on V25 (6.6 kernel, cgroup v2 unified):
#   1. Create cgroup v2 /sys/fs/cgroup/agentgateway/agents/ (writable cgroup.subtree_control)
#   2. Install system-level CA (certs/ca-cert.pem)
#   3. nftables REDIRECT: cgroup v2 "agentgateway" subtree → :8444
#   4. (Optional) Load BPF-LSM enforcement sandbox (agent_lsm loader)
#
# This is the 方案B counterpart of setup_iptables.sh (V20/cgroup v1). The V20
# script (iptables-legacy + net_cls) is preserved unchanged for dual-platform
# support. start.sh auto-detects which platform it is on.
#
# Usage: sudo bash setup_v25.sh              # setup
#        sudo bash setup_v25.sh --cleanup     # remove nftables rules + cgroup
#        sudo bash setup_v25.sh --bpf         # also load BPF-LSM (after setup)

set -uo pipefail

# Fix HOME when invoked via sudo without --preserve-env
if [[ -n "${SUDO_USER:-}" && "$HOME" == "/root" ]]; then
    HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CGROUP_ROOT="/sys/fs/cgroup"
CGROUP_AGW="$CGROUP_ROOT/agentgateway"
CGROUP_AGENTS="$CGROUP_AGW/agents"
REDIRECT_PORT=8444
NFT_TABLE="inet agentgateway"
HTTPS_PORTS="443, 8443, 9443"

# ─── Help ──────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    cat <<EOF
AgentGateway V25 setup (cgroup v2 + nftables + BPF-LSM)

Usage: sudo bash $0 [--cleanup] [--bpf]

Without flags: creates cgroup v2 subtree, installs CA, sets nftables REDIRECT.
  --cleanup    remove nftables table + cgroup subtree
  --bpf        also load the BPF-LSM enforcement sandbox (agent_lsm)

Prerequisites: V25 / 6.6 kernel, root, nft, bpf LSM enabled.
Verify:  cat /sys/kernel/security/lsm | grep bpf
         nft list table inet agentgateway
EOF
    exit 0
fi

if [[ $EUID -ne 0 ]]; then
    echo "[setup-v25] must run as root: sudo $0 ${*:-}" >&2
    exit 1
fi

# ─── Cleanup mode ──────────────────────────────────────────────────────────
if [[ "${1:-}" == "--cleanup" ]]; then
    echo "[setup-v25] Cleanup: removing nftables table + cgroup subtree..."
    # Remove BPF-LSM if loaded (kill the loader process)
    pkill -TERM -f 'bpf/agent_lsm$' 2>/dev/null && echo "[setup-v25] stopped agent_lsm loader" || true
    sleep 1
    pkill -KILL -f 'bpf/agent_lsm$' 2>/dev/null || true
    # Unpin BPF maps
    rm -rf /sys/fs/bpf/agentgateway 2>/dev/null && echo "[setup-v25] removed BPF map pins" || true
    # Remove nftables rules
    nft delete table inet agentgateway 2>/dev/null && echo "[setup-v25] removed nftables table" || true
    # Remove cgroup subtree (processes must have exited first)
    rmdir "$CGROUP_AGENTS" 2>/dev/null || true
    rmdir "$CGROUP_AGW" 2>/dev/null || true
    if [[ ! -d "$CGROUP_AGW" ]]; then
        echo "[setup-v25] cgroup subtree removed"
    else
        echo "[setup-v25] WARNING: $CGROUP_AGW still exists (processes still in it?)"
    fi
    echo "[setup-v25] Cleanup complete."
    exit 0
fi

# ─── 1. Verify platform (cgroup v2 + bpf LSM) ──────────────────────────────
echo "[setup-v25] Verifying V25 platform..."
if [[ "$(stat -fc %T "$CGROUP_ROOT" 2>/dev/null)" != "cgroup2fs" ]]; then
    echo "[setup-v25] ERROR: $CGROUP_ROOT is not cgroup v2 (cgroup2fs)" >&2
    echo "[setup-v25] This script is for V25 (cgroup v2 unified). Use setup_iptables.sh for V20." >&2
    exit 1
fi
if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
    echo "[setup-v25] WARNING: bpf LSM not in /sys/kernel/security/lsm — BPF-LSM enforcement unavailable" >&2
    echo "[setup-v25] transparent proxy will still work, but --bpf will fail" >&2
fi

# ─── 2. Create cgroup v2 subtree ───────────────────────────────────────────
echo "[setup-v25] Creating cgroup v2 subtree: $CGROUP_AGW..."
mkdir -p "$CGROUP_AGENTS"

# Enable controllers needed (none strictly required for socket cgroupv2 match,
# but enable memory + pids for resource tracking if available)
AVAILABLE_CTRLS="$(cat "$CGROUP_ROOT/cgroup.controllers" 2>/dev/null)"
if echo "$AVAILABLE_CTRLS" | grep -qw memory; then
    echo "+memory" > "$CGROUP_ROOT/cgroup.subtree_control" 2>/dev/null || true
fi
if echo "$AVAILABLE_CTRLS" | grep -qw pids; then
    echo "+pids" > "$CGROUP_ROOT/cgroup.subtree_control" 2>/dev/null || true
fi

# Make agents/ subtree writable by non-root (so agw-admit can create per-agent cgroups)
# cgroup v2: chmod the directory so non-root can write cgroup.procs
chmod 775 "$CGROUP_AGW" "$CGROUP_AGENTS"
# Ensure the calling user can create sub-cgroups under agents/
SETUP_USER="${SUDO_USER:-$(whoami)}"
SETUP_UID="$(id -u "$SETUP_USER")"
chown "$SETUP_UID" "$CGROUP_AGENTS" 2>/dev/null || true
echo "[setup-v25] cgroup subtree ready: $CGROUP_AGENTS (owner: $SETUP_USER)"

# ─── 3. Install system-level CA ────────────────────────────────────────────
CA_SRC="$SCRIPT_DIR/certs/ca-cert.pem"
CA_DST="/usr/local/share/ca-certificates/agentgateway-ca.crt"

# If CA doesn't exist, generate it by running the Rust binary briefly
if [[ ! -f "$CA_SRC" ]]; then
    echo "[setup-v25] CA not found at $CA_SRC, generating via agentgateway..."
    if [[ -x "$SCRIPT_DIR/target/release/agentgateway" ]]; then
        timeout 3 "$SCRIPT_DIR/target/release/agentgateway" --port 0 2>/dev/null || true
    elif [[ -x "$SCRIPT_DIR/target/debug/agentgateway" ]]; then
        timeout 3 "$SCRIPT_DIR/target/debug/agentgateway" --port 0 2>/dev/null || true
    else
        echo "[setup-v25] WARNING: agentgateway binary not found. Build with: cargo build --release" >&2
    fi
fi

if [[ -f "$CA_SRC" ]]; then
    echo "[setup-v25] Installing AgentGateway CA to $CA_DST..."
    cp "$CA_SRC" "$CA_DST"
    chmod 644 "$CA_DST"
    update-ca-certificates 2>&1
    # Verify CA is in the system bundle by fingerprint
    CA_FP="$(openssl x509 -in "$CA_DST" -fingerprint -noout 2>/dev/null | cut -d= -f2)"
    verify_ca_in_bundle() {
        awk 'BEGIN{n=0} /BEGIN CERT/{n++; f="/tmp/_agw_v25_"n".pem"} {print > f}' \
            /etc/ssl/certs/ca-certificates.crt 2>/dev/null
        for f in /tmp/_agw_v25_*.pem; do
            [[ -f "$f" ]] || continue
            fp="$(openssl x509 -in "$f" -fingerprint -noout 2>/dev/null | cut -d= -f2)"
            rm -f "$f"
            [[ "$fp" == "$CA_FP" ]] && return 0
        done
        rm -f /tmp/_agw_v25_*.pem 2>/dev/null
        return 1
    }
    if ! verify_ca_in_bundle; then
        echo "[setup-v25] CA not in bundle after update, rebuilding with --fresh..." >&2
        update-ca-certificates --fresh 2>&1
    fi
    if verify_ca_in_bundle; then
        echo "[setup-v25] System CA installed and verified in ca-certificates.crt"
    else
        echo "[setup-v25] ERROR: CA fingerprint not found in ca-certificates.crt!" >&2
    fi
    rm -f /tmp/_agw_v25_*.pem 2>/dev/null
else
    echo "[setup-v25] WARNING: $CA_SRC not found — CA generation failed" >&2
fi

# Also install to NSS DB for Chrome/Chromium
if command -v certutil &>/dev/null; then
    NSSDB="$HOME/.pki/nssdb"
    mkdir -p "$NSSDB"
    certutil -d "sql:$NSSDB" -D -n "mitmproxy" 2>/dev/null || true
    certutil -d "sql:$NSSDB" -D -n "agentgateway" 2>/dev/null || true
    if [[ -f "$CA_SRC" ]]; then
        certutil -d "sql:$NSSDB" -A -t "C,," -n "agentgateway" -i "$CA_SRC" 2>/dev/null || true
        echo "[setup-v25] NSS DB CA installed (nickname: agentgateway)"
    fi
fi

# ─── 4. iptables-legacy REDIRECT rules (cgroup v2 path match) ──────────────
# On V25 (kernel 6.6, cgroup v2), nftables `socket cgroupv2` match in the NAT
# OUTPUT chain does NOT reliably redirect traffic (the socket→cgroup association
# is not visible at the dstnat hook for locally-generated connect() traffic).
# iptables-legacy with `-m cgroup --path` works correctly because the xt_cgroup
# module matches the cgroup path at the OUTPUT nat hook after the socket is
# fully associated. SO_ORIGINAL_DST returns the pre-NAT destination (works with
# iptables-legacy conntrack).
echo "[setup-v25] Setting iptables-legacy REDIRECT rules (cgroup v2 '/agentgateway' → :$REDIRECT_PORT)..."

# Clean any stale nftables table from prior runs
nft delete table inet agentgateway 2>/dev/null || true

iptables-legacy -t nat -F OUTPUT 2>/dev/null || true

# Parse HTTPS_PORTS (comma-separated) and add a REDIRECT rule for each
OLD_IFS="$IFS"; IFS=','
for port in $HTTPS_PORTS; do
    port=$(echo "$port" | tr -d ' ')
    [[ -z "$port" ]] && continue
    iptables-legacy -t nat -A OUTPUT \
        -m cgroup --path agentgateway \
        -p tcp --dport "$port" \
        -j REDIRECT --to-ports "$REDIRECT_PORT"
done
IFS="$OLD_IFS"

echo "[setup-v25] iptables-legacy NAT rules set:"
iptables-legacy -t nat -L OUTPUT -n 2>/dev/null


# ─── 5. Load BPF-LSM (optional, --bpf flag) ────────────────────────────────
if [[ "${1:-}" == "--bpf" || "${2:-}" == "--bpf" ]]; then
    LSM_BIN="$SCRIPT_DIR/bpf/agent_lsm"
    if [[ ! -x "$LSM_BIN" ]]; then
        echo "[setup-v25] Building BPF tools..." >&2
        (cd "$SCRIPT_DIR/bpf" && make) || {
            echo "[setup-v25] ERROR: BPF build failed" >&2
            exit 1
        }
    fi
    echo "[setup-v25] Loading BPF-LSM enforcement sandbox..."
    # Kill any existing loader first
    pkill -TERM -f 'bpf/agent_lsm$' 2>/dev/null || true
    sleep 1
    # Start loader in background (it pins maps to /sys/fs/bpf/agentgateway/)
    AGW_ENFORCE_FILE_WRITE="${AGW_ENFORCE_FILE_WRITE:-0}" \
        nohup "$LSM_BIN" > "$SCRIPT_DIR/logs/bpf_lsm.log" 2>&1 &
    LSM_PID=$!
    echo "[setup-v25] BPF-LSM loader started (pid=$LSM_PID, log=logs/bpf_lsm.log)"
    # Wait for maps to be pinned
    for i in $(seq 1 20); do
        [[ -f /sys/fs/bpf/agentgateway/audit_buf ]] && break
        sleep 0.5
    done
    if [[ -f /sys/fs/bpf/agentgateway/audit_buf ]]; then
        echo "[setup-v25] BPF maps pinned to /sys/fs/bpf/agentgateway/"
    else
        echo "[setup-v25] WARNING: BPF maps not pinned — check logs/bpf_lsm.log" >&2
    fi
fi

echo "[setup-v25] ─────────────────────────────────────"
echo "[setup-v25] Setup complete (V25 / cgroup v2 / iptables-legacy + BPF-LSM)."
echo "[setup-v25] Verify:   iptables-legacy -t nat -L OUTPUT -n"
echo "[setup-v25] Verify:   ls /sys/fs/cgroup/agentgateway/agents/"
echo "[setup-v25] Cleanup:  sudo bash $0 --cleanup"
