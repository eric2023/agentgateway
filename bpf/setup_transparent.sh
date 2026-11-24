#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
# AgentGateway 方案B P3 transparent proxy setup (run as root).
#
# 1. Install the AgentGateway CA system-wide (/etc/ssl/certs/) — replaces 方案A's
#    per-process env-var CA trust with a system-level trust (no app modification).
# 2. nftables: redirect non-root :443 -> :8444. Excludes root so the gateway's own
#    outbound forwarding is not re-redirected (loop prevention). For a multi-user
#    production setup prefer cgroup-based matching instead of skuid.
# 3. Start the transparent proxy in the foreground.
#
# Teardown:
#   nft delete table inet agentgateway
#   rm -f /etc/ssl/certs/agentgateway-ca.pem && update-ca-certificates
set -e
cd "$(dirname "$0")/.."

GATEWAY_PORT=${GATEWAY_PORT:-8444}

if [[ $EUID -ne 0 ]]; then
    echo "must run as root: sudo $0"
    exit 1
fi

# 1. system-wide CA trust
install -m 644 certs/ca-cert.pem /etc/ssl/certs/agentgateway-ca.pem
update-ca-certificates
echo "[tproxy] CA installed system-wide"

# 2. nftables redirect (non-root :443 -> :8444)
nft delete table inet agentgateway 2>/dev/null || true
nft add table inet agentgateway
nft add chain inet agentgateway output '{ type nat hook output priority -100; policy accept; }'
nft add rule inet agentgateway output meta skuid != 0 tcp dport 443 redirect to ":$GATEWAY_PORT"
echo "[tproxy] nftables:"
nft list chain inet agentgateway output

# 3. run transparent proxy
echo "[tproxy] starting transparent proxy on 127.0.0.1:$GATEWAY_PORT ..."
exec python3 gateway/transparent_proxy.py
