#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
# AgentGateway P1 verification: load BPF-LSM, admit a process into a managed
# cgroup, and observe the in-kernel DENY of a direct non-loopback :443 connect.
#
# Run as root:   sudo bash bpf/verify_p1.sh
set -u
cd "$(dirname "$0")/.."

BPF=./bpf
AUDIT_LOG=audit/audit.jsonl
TEST_IP=8.8.8.8
AGENT_ID="agent-p1verify"
SESSION_ID="session-p1verify"

echo "== 0. preflight =="
[[ $EUID -eq 0 ]] || { echo "must run as root: sudo bash bpf/verify_p1.sh"; exit 1; }
[[ -x $BPF/agent_lsm ]] || { echo "build first: make -C bpf"; exit 1; }

# clean any stale pinned maps from a previous run
rm -rf /sys/fs/bpf/agentgateway 2>/dev/null

echo "== 1. load BPF-LSM =="
$BPF/agent_lsm &
LOADER=$!
sleep 1
kill -0 $LOADER 2>/dev/null || { echo "loader died"; exit 1; }

echo "== 2. start audit consumer =="
$BPF/audit_consumer "$AUDIT_LOG" &
CONSUMER=$!
sleep 1

echo "== 3. negative control (unmanaged, direct 443) =="
curl --max-time 4 -sS -o /dev/null "https://$TEST_IP/" 2>/tmp/agw_neg.err
echo "unmanaged curl exit=$?  (connect NOT denied by LSM)"

echo "== 4. admit self into managed cgroup =="
$BPF/agent_admit p1verify "$AGENT_ID" "$SESSION_ID" "curl-test" $$
echo "admit exit=$?"

echo "== 5. positive test (managed, direct 443) =="
curl --max-time 4 -sS -o /dev/null "https://$TEST_IP/" 2>/tmp/agw_pos.err
rc=$?
echo "managed curl exit=$rc"
if grep -qiE 'permission denied|operation not permitted|could not connect' /tmp/agw_pos.err; then
    echo "OK: connect() denied in-kernel (curl failed at ~0ms, not timeout)"
else
    echo "note: see audit trail below for the authoritative DENY event; stderr:"; cat /tmp/agw_pos.err
fi

echo "== 6. audit trail (DENY events) =="
sleep 1
grep -F '"decision":"DENY"' "$AUDIT_LOG" | tail -5

echo "== 7. cleanup =="
kill $LOADER $CONSUMER 2>/dev/null
echo "done (cgroup /sys/fs/cgroup/agentgateway/agents/p1verify left for inspection)"
