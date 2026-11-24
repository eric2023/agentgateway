#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Build the agentgateway-bpf DEB package (方案B kernel-level components).
# Usage: bash packaging/build_deb.sh
set -e
cd "$(dirname "$0")/.."   # repo root

VERSION=1.0.0
PKG=agentgateway-bpf
ARCH=amd64
ROOT=packaging/debian
OUT=dist

echo "[deb] 1/3 compile"
make -C bpf all

echo "[deb] 2/3 stage files"
rm -rf "$ROOT/usr"
install -d -m 755 "$ROOT/usr/lib/agentgateway/bpf" \
         "$ROOT/usr/lib/agentgateway/gateway" \
         "$ROOT/usr/lib/agentgateway/certs" \
         "$ROOT/usr/share/doc/$PKG"

# binaries + helper scripts
install -m 755 bpf/agent_lsm bpf/audit_consumer bpf/agent_admit \
    bpf/agent_landlock bpf/agent_uprobe bpf/agent_uprobe_consumer \
    bpf/seccomp_confirm bpf/cgroupid bpf/setup_transparent.sh \
    "$ROOT/usr/lib/agentgateway/bpf/"

# BPF objects + vmlinux.h (reference / re-load)
install -m 644 bpf/agent_lsm.bpf.o bpf/agent_uprobe.bpf.o bpf/vmlinux.h \
    "$ROOT/usr/lib/agentgateway/bpf/"

# gateway python modules (transparent_proxy imports agentgatewayd)
install -m 644 gateway/agentgatewayd.py gateway/transparent_proxy.py \
    gateway/gen_ca.py "$ROOT/usr/lib/agentgateway/gateway/"

# CA cert (private key never packaged)
install -m 644 certs/ca-cert.pem "$ROOT/usr/lib/agentgateway/certs/"

# one-click runtime script
install -m 755 run_agentgateway.sh "$ROOT/usr/lib/agentgateway/"

# changelog (gzipped)
{
    echo "agentgateway-bpf ($VERSION) unstable; urgency=low"
    echo ""
    echo "  * BPF-LSM kernel-level agent governance (方案B): 网络强制/文件边界/透明代理/明文采集/自保护"
    echo ""
    echo " -- AgentGateway Team <agentgateway@uniontech.com>  $(date -R)"
} > "$ROOT/usr/share/doc/$PKG/changelog"
gzip -9 -f "$ROOT/usr/share/doc/$PKG/changelog"

echo "[deb] 3/3 build package"
mkdir -p "$OUT"
fakeroot dpkg-deb --build --root-owner-group "$ROOT" "$OUT/${PKG}_${VERSION}_${ARCH}.deb"

echo "[deb] done: $OUT/${PKG}_${VERSION}_${ARCH}.deb"
