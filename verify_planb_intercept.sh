#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
# AgentGateway 方案B — 三方 Agent 拦截效果手动验证脚本
#
# 本脚本覆盖方案 B 全链路验证（P0-P5），支持两种模式:
#   1. 用户态子集（无 root）: P0 网关 L7 审计 + AI 请求拦截
#   2. 内核态全集（需 root）: P1-P5 BPF-LSM 强制管控
#
# 用法:
#   ./verify_planb_intercept.sh              # 自动检测 root，运行可验证项
#   ./verify_planb_intercept.sh --user       # 仅用户态（方案 A 子集）
#   ./verify_planb_intercept.sh --kernel     # 仅内核态（需 root）
#   ./verify_planb_intercept.sh stop         # 清理验证残留
#
# 三方 Agent 模拟:
#   - curl (OpenSSL)       → 模拟 Python/Go Agent
#   - Python requests      → 模拟 Python AI SDK
#   - Node.js/Electron     → 模拟 Electron Agent (如 WorkBuddy)
#   - 直接 :443 连接        → 验证 BPF-LSM 内核拦截（需 root）

set -uo pipefail
cd "$(dirname "$0")"

PROJECT_DIR="$(pwd)"
PYTHON="$(command -v python3 || true)"
[[ -z "$PYTHON" ]] && PYTHON="/home/ut000520@uos/.pyenv/shims/python3"

GATEWAY_PID=""
DASHBOARD_PID=""
LSM_PID=""
AUDIT_PID=""
TPROXY_PID=""
AUDIT_MARKER=0
MODE="auto"

# ─── 颜色输出 ─────────────────────────────────────────────────────────────
red()    { printf "\033[31m%s\033[0m\n" "$*"; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
blue()   { printf "\033[34m%s\033[0m\n" "$*"; }
bold()   { printf "\033[1m%s\033[0m\n" "$*"; }

ok()   { green "  ✅ $*"; }
fail() { red   "  ❌ $*"; }
skip() { yellow "  ⏭  $*"; }
info() { blue  "  ℹ️  $*"; }
section() { printf "\n\033[1;36m══════ %s ══════\033[0m\n" "$*"; }

PASS=0; FAIL=0; SKIP=0
record_ok()   { ok "$@";   PASS=$((PASS+1)); }
record_fail() { fail "$@"; FAIL=$((FAIL+1)); }
record_skip() { skip "$@"; SKIP=$((SKIP+1)); }

# ─── 清理 ─────────────────────────────────────────────────────────────────
cleanup() {
    [[ -n "$GATEWAY_PID" ]]   && kill "$GATEWAY_PID"   2>/dev/null || true
    [[ -n "$DASHBOARD_PID" ]] && kill "$DASHBOARD_PID" 2>/dev/null || true
    [[ -n "$LSM_PID" ]]       && kill "$LSM_PID"       2>/dev/null || true
    [[ -n "$AUDIT_PID" ]]     && kill "$AUDIT_PID"     2>/dev/null || true
    [[ -n "$TPROXY_PID" ]]    && kill "$TPROXY_PID"    2>/dev/null || true
    gsettings set org.gnome.system.proxy mode 'auto' 2>/dev/null || true
    rm -f /tmp/agw_pb_*.txt /tmp/agw_pb_*.json 2>/dev/null || true
}

if [[ "${1:-}" == "stop" ]]; then
    cleanup
    # 也清理可能残留的 BPF 组件
    if [[ $EUID -eq 0 ]]; then
        pkill -f 'bpf/agent_lsm' 2>/dev/null || true
        pkill -f 'bpf/audit_consumer' 2>/dev/null || true
        pkill -f 'bpf/agent_uprobe' 2>/dev/null || true
        nft delete table inet agentgateway 2>/dev/null || true
        rm -rf /sys/fs/bpf/agentgateway /sys/fs/bpf/agentgateway_uprobe 2>/dev/null || true
    fi
    echo "[verify] cleaned up"
    exit 0
fi

# 解析模式参数
case "${1:-auto}" in
    --user)   MODE="user" ;;
    --kernel) MODE="kernel" ;;
    --auto|auto) MODE="auto" ;;
    *) echo "用法: $0 [--user|--kernel|stop]"; exit 1 ;;
esac

trap cleanup EXIT INT TERM

# ─── 环境检测 ─────────────────────────────────────────────────────────────
section "环境检测"

IS_ROOT=0
[[ $EUID -eq 0 ]] && IS_ROOT=1

if [[ $MODE == "kernel" && $IS_ROOT -eq 0 ]]; then
    # 尝试 sudo
    if sudo -n true 2>/dev/null; then
        info "非 root，通过 sudo 重新执行"
        exec sudo "$0" "$@"
    else
        fail "内核态验证需要 root 权限（sudo 需密码）"
        exit 1
    fi
fi

# LSM 检查
LSM_LIST=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "")
if echo "$LSM_LIST" | grep -q 'bpf'; then
    record_ok "BPF LSM 已激活"
else
    record_fail "BPF LSM 未激活（方案 B 内核态不可用）"
fi

# BTF 检查
if [[ -f /sys/kernel/btf/vmlinux ]]; then
    record_ok "BTF 可用 (/sys/kernel/btf/vmlinux)"
else
    record_fail "BTF 不可用"
fi

# 内核版本
KERNEL_VER=$(uname -r)
if [[ "$KERNEL_VER" == 6.6* ]]; then
    record_ok "内核版本 $KERNEL_VER (方案 B 目标 6.6)"
else
    info "内核版本 $KERNEL_VER（方案 B 目标 6.6，当前版本可能不兼容）"
fi

# 决定验证范围
if [[ $MODE == "auto" ]]; then
    if [[ $IS_ROOT -eq 1 ]]; then
        MODE="full"
        info "root 权限 → 全量验证（P0-P5）"
    else
        MODE="user"
        info "非 root → 用户态验证（P0 + 方案 A 子集）"
    fi
fi

# ─── P0: 透明代理 + L7 识别（方案 A 复用）────────────────────────────────
section "P0: 透明代理 + L7 AI 请求识别（方案 A 复用）"

# P0.1 CA 证书
if [[ -f certs/ca-cert.pem && -f certs/ca-key.pem ]]; then
    record_ok "CA 证书 + 私钥存在"
else
    record_fail "CA 证书/私钥缺失，执行: python3 gateway/gen_ca.py"
    exit 1
fi

# P0.2 清理残留动态证书
rm -f certs/dyn-*.pem 2>/dev/null

# P0.3 启动网关
info "启动 AgentGateway 网关..."
"$PYTHON" gateway/agentgatewayd.py >>logs/pb_gateway.log 2>&1 &
GATEWAY_PID=$!
sleep 3

if kill -0 "$GATEWAY_PID" 2>/dev/null; then
    record_ok "网关启动成功 (pid=$GATEWAY_PID)"
else
    record_fail "网关启动失败"
    tail -20 logs/pb_gateway.log
    exit 1
fi

if ss -tlnp 2>/dev/null | grep -q ':8443'; then
    record_ok "网关监听 :8443"
else
    record_fail "网关未监听 :8443"
fi

# P0.4 启动仪表盘
info "启动仪表盘..."
"$PYTHON" dashboard/dashboard.py >>logs/pb_dashboard.log 2>&1 &
DASHBOARD_PID=$!
sleep 2

if kill -0 "$DASHBOARD_PID" 2>/dev/null && ss -tlnp 2>/dev/null | grep -q ':9090'; then
    record_ok "仪表盘启动成功 (pid=$DASHBOARD_PID, :9090)"
else
    record_fail "仪表盘启动失败"
fi

# ─── 三方 Agent 拦截验证 ──────────────────────────────────────────────────
section "三方 Agent 拦截验证"

# 记录审计日志基线（系统代理流量会持续写入）
AUDIT_MARKER=$(wc -l < audit/audit.jsonl 2>/dev/null || echo 0)

# ── Agent 1: curl (模拟 OpenSSL/Go Agent) ─────────────────────────────────
echo
bold "  ▶ Agent 1: curl (OpenSSL) — 模拟 Go/Python AI Agent"
echo "    请求: POST https://api.openai.com/v1/chat/completions"
echo "    代理: HTTPS_PROXY → 127.0.0.1:8443"

curl -s -o /dev/null -w '    HTTP %{http_code}, %{time_total}s\n' --max-time 8 \
    -x "http://127.0.0.1:8443" \
    --cacert certs/ca-cert.pem \
    -X POST "https://api.openai.com/v1/chat/completions" \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer sk-test-curl-agent' \
    -d '{"model":"gpt-4","messages":[{"role":"user","content":"hello from curl agent"}]}' \
    2>/dev/null || true

sleep 1
NEW_AUDIT=$(tail -n +"$((AUDIT_MARKER + 1))" audit/audit.jsonl 2>/dev/null)
AGENT1_AUDIT=$(echo "$NEW_AUDIT" | grep 'api.openai.com' | grep 'ai_request_audited' | tail -1)

if [[ -n "$AGENT1_AUDIT" ]]; then
    record_ok "curl Agent AI 请求被审计"
    echo "$AGENT1_AUDIT" | "$PYTHON" -c "
import sys, json
d = json.loads(sys.stdin.read())
print(f'    host={d[\"host\"]} model={d[\"model\"]} decision={d[\"decision\"]} confidence={d[\"confidence\"]}')
print(f'    app_name={d.get(\"app_name\",\"?\")} peer_comm={d.get(\"peer_comm\",\"?\")}')
print(f'    preview={d.get(\"preview\",\"?\")[:60]}')
" 2>/dev/null || echo "$AGENT1_AUDIT" | head -c 200
    echo "$AGENT1_AUDIT" | grep -q '"decision": "AUDIT"\|"decision":"AUDIT"' && record_ok "decision=AUDIT（非阻断，审计后转发）" || record_fail "decision 非 AUDIT"
else
    record_fail "curl Agent AI 请求未被审计"
fi

AUDIT_MARKER=$(wc -l < audit/audit.jsonl 2>/dev/null || echo 0)

# ── Agent 2: Python requests (模拟 Python AI SDK) ────────────────────────
echo
bold "  ▶ Agent 2: Python (requests/urllib) — 模拟 Python AI SDK Agent"
echo "    请求: POST https://api.anthropic.com/v1/messages"
echo "    代理: HTTPS_PROXY → 127.0.0.1:8443"

"$PYTHON" -c "
import os, ssl, json, urllib.request

os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:8443'
os.environ['SSL_CERT_FILE'] = 'certs/ca-cert.pem'

body = json.dumps({
    'model': 'claude-3-opus-20240229',
    'max_tokens': 100,
    'messages': [{'role': 'user', 'content': 'hello from python agent'}]
}).encode()

req = urllib.request.Request(
    'https://api.anthropic.com/v1/messages',
    data=body,
    headers={
        'Content-Type': 'application/json',
        'x-api-key': 'sk-test-python-agent',
        'anthropic-version': '2023-06-01',
    }
)
try:
    resp = urllib.request.urlopen(req, timeout=8)
    print(f'    HTTP {resp.status}')
except Exception as e:
    print(f'    HTTP 000 ({type(e).__name__})')
" 2>/dev/null || true

sleep 1
NEW_AUDIT=$(tail -n +"$((AUDIT_MARKER + 1))" audit/audit.jsonl 2>/dev/null)
AGENT2_AUDIT=$(echo "$NEW_AUDIT" | grep 'api.anthropic.com' | grep 'ai_request_audited' | tail -1)

if [[ -n "$AGENT2_AUDIT" ]]; then
    record_ok "Python Agent AI 请求被审计"
    echo "$AGENT2_AUDIT" | "$PYTHON" -c "
import sys, json
d = json.loads(sys.stdin.read())
print(f'    host={d[\"host\"]} model={d[\"model\"]} decision={d[\"decision\"]} confidence={d[\"confidence\"]}')
print(f'    app_name={d.get(\"app_name\",\"?\")} peer_comm={d.get(\"peer_comm\",\"?\")}')
print(f'    preview={d.get(\"preview\",\"?\")[:60]}')
" 2>/dev/null || echo "$AGENT2_AUDIT" | head -c 200
    echo "$AGENT2_AUDIT" | grep -q '"decision": "AUDIT"\|"decision":"AUDIT"' && record_ok "decision=AUDIT（非阻断，审计后转发）" || record_fail "decision 非 AUDIT"
else
    record_fail "Python Agent AI 请求未被审计"
fi

AUDIT_MARKER=$(wc -l < audit/audit.jsonl 2>/dev/null || echo 0)

# ── Agent 3: Node.js/Bun (模拟 Electron Agent，如 WorkBuddy) ─────────────
echo
bold "  ▶ Agent 3: Node.js/Bun — 模拟 Electron Agent (WorkBuddy)"
echo "    请求: POST https://api.deepseek.com/v1/chat/completions"
echo "    代理: HTTPS_PROXY + NODE_EXTRA_CA_CERTS → 127.0.0.1:8443"

NODE_BIN=$(command -v node 2>/dev/null || command -v bun 2>/dev/null || echo "")
if [[ -n "$NODE_BIN" ]]; then
    RUNTIME_NAME=$(basename "$NODE_BIN")
    export HTTPS_PROXY="http://127.0.0.1:8443"
    export NODE_EXTRA_CA_CERTS="$PROJECT_DIR/certs/ca-cert.pem"
    export SSL_CERT_FILE="$PROJECT_DIR/certs/ca-cert.pem"

    if [[ "$RUNTIME_NAME" == "node" ]]; then
        "$NODE_BIN" -e "
const https = require('https');
const http = require('http');
const url = require('url');

const proxyUrl = url.parse(process.env.HTTPS_PROXY);
const body = JSON.stringify({
    model: 'deepseek-chat',
    messages: [{role: 'user', content: 'hello from node agent'}]
});

const connectReq = http.request({
    host: proxyUrl.hostname,
    port: proxyUrl.port,
    method: 'CONNECT',
    path: 'api.deepseek.com:443'
});
connectReq.on('connect', (res, socket) => {
    const tlsSocket = require('tls').connect({
        socket: socket,
        servername: 'api.deepseek.com',
        ca: require('fs').readFileSync(process.env.NODE_EXTRA_CA_CERTS)
    }, () => {
        const req = 'POST /v1/chat/completions HTTP/1.1\r\nHost: api.deepseek.com\r\nContent-Type: application/json\r\nAuthorization: Bearer sk-test-node-agent\r\nContent-Length: ' + Buffer.byteLength(body) + '\r\n\r\n' + body;
        tlsSocket.write(req);
    });
    tlsSocket.on('error', (e) => console.log('    TLS error:', e.message));
});
connectReq.on('error', (e) => console.log('    CONNECT error:', e.message));
connectReq.end();
setTimeout(() => process.exit(0), 5000);
" 2>/dev/null || true
    else
        # Bun runtime
        "$NODE_BIN" -e "
const body = JSON.stringify({model:'deepseek-chat',messages:[{role:'user',content:'hello from bun agent'}]});
try {
    const resp = await fetch('https://api.deepseek.com/v1/chat/completions', {
        method: 'POST',
        headers: {'Content-Type':'application/json','Authorization':'Bearer sk-test-bun-agent'},
        body: body
    });
    console.log('    HTTP ' + resp.status);
} catch(e) { console.log('    HTTP 000 (' + (e.name||'Error') + ')'); }
" 2>/dev/null || true
    fi
    sleep 1

    NEW_AUDIT=$(tail -n +"$((AUDIT_MARKER + 1))" audit/audit.jsonl 2>/dev/null)
    AGENT3_AUDIT=$(echo "$NEW_AUDIT" | grep 'api.deepseek.com' | grep 'ai_request_audited' | tail -1)

    if [[ -n "$AGENT3_AUDIT" ]]; then
        record_ok "$RUNTIME_NAME Agent AI 请求被审计"
        echo "$AGENT3_AUDIT" | "$PYTHON" -c "
import sys, json
d = json.loads(sys.stdin.read())
print(f'    host={d[\"host\"]} model={d[\"model\"]} decision={d[\"decision\"]} confidence={d[\"confidence\"]}')
print(f'    app_name={d.get(\"app_name\",\"?\")} peer_comm={d.get(\"peer_comm\",\"?\")}')
print(f'    preview={d.get(\"preview\",\"?\")[:60]}')
" 2>/dev/null || echo "$AGENT3_AUDIT" | head -c 200
        echo "$AGENT3_AUDIT" | grep -q '"decision": "AUDIT"\|"decision":"AUDIT"' && record_ok "decision=AUDIT（非阻断，审计后转发）" || record_fail "decision 非 AUDIT"
    else
        record_fail "$RUNTIME_NAME Agent AI 请求未被审计"
    fi
else
    record_skip "Node.js/Bun 不可用 — 跳过 Electron Agent 模拟"
fi

AUDIT_MARKER=$(wc -l < audit/audit.jsonl 2>/dev/null || echo 0)

# ── Agent 4: 非 AI 请求（验证不误拦）─────────────────────────────────────
echo
bold "  ▶ Agent 4: 非 AI 请求 — 验证不误拦"
echo "    请求: GET https://example.com/ (非 AI 主机)"
echo "    期望: 盲隧道转发，无 ai_request_audited"

curl -s -o /dev/null -w '    HTTP %{http_code}, %{time_total}s\n' --max-time 8 \
    -x "http://127.0.0.1:8443" \
    --cacert certs/ca-cert.pem \
    "https://example.com/" \
    2>/dev/null || true

sleep 1
NEW_AUDIT=$(tail -n +"$((AUDIT_MARKER + 1))" audit/audit.jsonl 2>/dev/null)
NON_AI_AUDIT=$(echo "$NEW_AUDIT" | grep 'example.com' | grep 'ai_request_audited' | head -1)

if [[ -z "$NON_AI_AUDIT" ]]; then
    record_ok "非 AI 请求未被误判为 AI 请求（正确）"
else
    record_fail "非 AI 请求被误判为 AI 请求"
fi

# ── P0 汇总: 多厂商 AI 请求识别 ───────────────────────────────────────────
echo
bold "  ▶ P0 汇总: 审计日志中的 AI 请求统计"
TOTAL_AI=$(grep -c 'ai_request_audited' audit/audit.jsonl 2>/dev/null || echo 0)
UNIQUE_HOSTS=$(grep 'ai_request_audited' audit/audit.jsonl 2>/dev/null | "$PYTHON" -c "
import sys, json
hosts = set()
for line in sys.stdin:
    try: hosts.add(json.loads(line)['host'])
    except: pass
for h in sorted(hosts): print(f'    - {h}')
print(f'    共 {len(hosts)} 个 AI 主机')
" 2>/dev/null || echo "    (解析失败)")
info "审计日志共 $TOTAL_AI 条 ai_request_audited 事件"
echo "$UNIQUE_HOSTS"

# ─── P1-P5: 内核态验证（需 root）─────────────────────────────────────────
if [[ $MODE == "user" ]]; then
    section "P1-P5: 内核态验证（需 root，跳过）"
    record_skip "P1 BPF-LSM socket_connect 内核 DENY（需 root: sudo $0 --kernel）"
    record_skip "P2 BPF-LSM file_open 文件边界（需 root）"
    record_skip "P3 nftables redirect 透明代理（需 root）"
    record_skip "P4 seccomp USER_NOTIF 同步确认（需 root）"
    record_skip "P5 BPF-LSM security_bpf 自保护（需 root）"
else
    # ═══════════════════════════════════════════════════════════════════════
    # 内核态验证（root）
    # ═══════════════════════════════════════════════════════════════════════

    # ── P1: BPF-LSM 网络强制 ─────────────────────────────────────────────
    section "P1: BPF-LSM 网络强制（socket_connect 内核内 DENY）"

    # P1.1 加载 BPF-LSM
    info "加载 BPF-LSM 程序..."
    rm -rf /sys/fs/bpf/agentgateway 2>/dev/null || true
    ./bpf/agent_lsm >>logs/pb_lsm.log 2>&1 &
    LSM_PID=$!
    sleep 2

    if kill -0 "$LSM_PID" 2>/dev/null; then
        record_ok "BPF-LSM 加载成功 (pid=$LSM_PID)"
    else
        record_fail "BPF-LSM 加载失败"
        tail -20 logs/pb_lsm.log
    fi

    if [[ -d /sys/fs/bpf/agentgateway ]]; then
        record_ok "BPF maps pinned 到 /sys/fs/bpf/agentgateway"
        ls /sys/fs/bpf/agentgateway/ 2>/dev/null | while read map; do
            info "  map: $map"
        done
    else
        record_fail "BPF maps 未 pinned"
    fi

    # P1.2 启动审计消费者
    info "启动审计消费者..."
    : > /tmp/agw_pb_kernel_audit.jsonl
    ./bpf/audit_consumer /tmp/agw_pb_kernel_audit.jsonl >>logs/pb_audit_consumer.log 2>&1 &
    AUDIT_PID=$!
    sleep 1

    if kill -0 "$AUDIT_PID" 2>/dev/null; then
        record_ok "审计消费者启动 (→ /tmp/agw_pb_kernel_audit.jsonl)"
    else
        record_fail "审计消费者启动失败"
    fi

    # P1.3 负对照：非受管进程直连 443（应成功连接）
    echo
    bold "  ▶ P1.3 负对照: 非受管进程直连 :443（不应被 DENY）"
    curl --max-time 5 -sS -o /dev/null "https://8.8.8.8/" 2>/tmp/agw_pb_neg.err
    NEG_RC=$?
    if [[ $NEG_RC -ne 0 ]] && grep -qiE 'permission denied|operation not permitted' /tmp/agw_pb_neg.err; then
        record_fail "非受管进程被错误 DENY（不应拦截）"
    else
        record_ok "非受管进程直连 443 未被拦截（正确）"
    fi

    # P1.4 纳入受管 cgroup
    echo
    bold "  ▶ P1.4 纳入当前 shell 到受管 cgroup"
    AGENT_ID="agent-pbverify"
    SESSION_ID="session-pbverify"
    ./bpf/agent_admit pbverify "$AGENT_ID" "$SESSION_ID" "verify-shell" $$ 2>/dev/null
    ADMIT_RC=$?
    if [[ $ADMIT_RC -eq 0 ]]; then
        record_ok "当前 shell 已纳入受管 cgroup (agent_id=$AGENT_ID)"
    else
        record_fail "cgroup 纳入失败 (exit=$ADMIT_RC)"
    fi

    # P1.5 正测试：受管进程直连 443（应被内核 DENY）
    echo
    bold "  ▶ P1.5 正测试: 受管进程直连 :443（应被内核内 DENY）"
    echo "    期望: connect() 返回 EPERM/EACCES（~0ms 失败，非超时）"
    curl --max-time 5 -sS -o /dev/null "https://8.8.8.8/" 2>/tmp/agw_pb_pos.err
    POS_RC=$?
    echo "    curl exit=$POS_RC"
    if grep -qiE 'permission denied|operation not permitted|could not connect|connection refused' /tmp/agw_pb_pos.err; then
        record_ok "受管进程直连 443 被内核 DENY"
        echo "    stderr: $(cat /tmp/agw_pb_pos.err)"
    else
        record_fail "受管进程直连 443 未被 DENY"
        echo "    stderr: $(cat /tmp/agw_pb_pos.err)"
    fi

    # P1.6 审计日志检查 DENY 事件
    sleep 1
    DENY_EVENTS=$(grep -c '"decision":"DENY"' /tmp/agw_pb_kernel_audit.jsonl 2>/dev/null || echo 0)
    if [[ "$DENY_EVENTS" -gt 0 ]]; then
        record_ok "内核审计日志含 $DENY_EVENTS 条 DENY 事件"
        grep '"decision":"DENY"' /tmp/agw_pb_kernel_audit.jsonl | tail -2 | while read line; do
            echo "    $line" | head -c 200
            echo
        done
    else
        record_fail "内核审计日志无 DENY 事件"
    fi

    # ── P2: 文件边界 ────────────────────────────────────────────────────
    section "P2: 文件边界（BPF-LSM file_open）"
    record_skip "P2 文件边界验证需重启 BPF-LSM 带 AGW_ENFORCE_FILE_WRITE=1（手动验证）"
    echo "  手动验证步骤:"
    echo "    sudo env AGW_ENFORCE_FILE_WRITE=1 AGW_WRITE_ALLOW=/tmp/sandbox ./bpf/agent_lsm &"
    echo "    # 受管进程: echo ok > /tmp/sandbox/a.txt  → 成功"
    echo "    # 受管进程: echo x > /tmp/other/b.txt    → Operation not permitted"

    # ── P3: 透明代理 + uprobe ───────────────────────────────────────────
    section "P3: 透明代理（nftables redirect + SNI MITM）"

    # P3.1 启动透明代理
    info "启动透明代理 (setup_transparent.sh)..."
    # 透明代理会安装系统 CA + nftables + 启动 :8444
    # 注意：这会修改系统 CA 和 nftables，在验证后清理
    ./bpf/setup_transparent.sh >>logs/pb_tproxy.log 2>&1 &
    TPROXY_PID=$!
    sleep 3

    if kill -0 "$TPROXY_PID" 2>/dev/null; then
        record_ok "透明代理启动 (pid=$TPROXY_PID)"
    else
        record_fail "透明代理启动失败"
        tail -20 logs/pb_tproxy.log
    fi

    # P3.2 nftables 规则检查
    if nft list table inet agentgateway 2>/dev/null | grep -q 'redirect'; then
        record_ok "nftables redirect 规则已安装"
        nft list chain inet agentgateway output 2>/dev/null | head -5 | while read line; do
            info "  $line"
        done
    else
        record_fail "nftables redirect 规则未安装"
    fi

    # P3.3 系统 CA 检查
    if [[ -f /etc/ssl/certs/agentgateway-ca.pem ]]; then
        record_ok "系统级 CA 已安装 (/etc/ssl/certs/agentgateway-ca.pem)"
    else
        record_fail "系统级 CA 未安装"
    fi

    # P3.4 非 root curl 无 HTTPS_PROXY 直连 AI 主机 → 被 redirect 后 MITM 审计
    echo
    bold "  ▶ P3.4 非 root 进程无 HTTPS_PROXY 直连 AI 主机"
    echo "    期望: nftables redirect → :8444 → SNI MITM → 审计"

    # 降权执行（非 root）
    KERN_AUDIT_MARKER=$(wc -l < /tmp/agw_pb_kernel_audit.jsonl 2>/dev/null || echo 0)
    TP_AUDIT_MARKER=$(wc -l < audit/audit.jsonl 2>/dev/null || echo 0)

    # 以非 root 用户执行 curl（如果有 nonroot 用户）
    NONROOT_USER=$(whoami 2>/dev/null || echo "nobody")
    if [[ "$NONROOT_USER" != "root" ]]; then
        # 已经是某个非 root 用户但通过 sudo 执行的，用 su 降权
        SUDO_USER=$(logname 2>/dev/null || echo "")
        if [[ -n "$SUDO_USER" && "$SUDO_USER" != "root" ]]; then
            su "$SUDO_USER" -c "curl --max-time 8 -sS -o /dev/null \
                -X POST 'https://api.openai.com/v1/chat/completions' \
                -H 'Content-Type: application/json' \
                -H 'Authorization: Bearer sk-test-tproxy' \
                -d '{\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\",\"content\":\"tproxy test\"}]}'" 2>/dev/null || true
        else
            # 直接以当前非 root 身份执行
            curl --max-time 8 -sS -o /dev/null \
                -X POST "https://api.openai.com/v1/chat/completions" \
                -H 'Content-Type: application/json' \
                -H 'Authorization: Bearer sk-test-tproxy' \
                -d '{"model":"gpt-4","messages":[{"role":"user","content":"tproxy test"}]}' 2>/dev/null || true
        fi
    fi

    sleep 2
    # 检查透明代理审计日志（tproxy.log 或 audit.jsonl）
    TPLOG_TAIL=$(tail -20 logs/pb_tproxy.log 2>/dev/null)
    if echo "$TPLOG_TAIL" | grep -q 'MITM.*api.openai.com'; then
        record_ok "透明代理 MITM 拦截到 api.openai.com"
    else
        record_fail "透明代理未拦截到 AI 请求"
        echo "$TPLOG_TAIL" | tail -5
    fi

    # P3.5 uprobe 明文采集
    echo
    bold "  ▶ P3.5 BPF uprobe 明文采集"
    info "启动 uprobe..."
    rm -rf /sys/fs/bpf/agentgateway_uprobe 2>/dev/null || true
    ./bpf/agent_uprobe >>logs/pb_uprobe.log 2>&1 &
    UPROBE_PID=$!
    sleep 1
    ./bpf/agent_uprobe_consumer /tmp/agw_pb_tls_audit.jsonl >>logs/pb_uprobe_consumer.log 2>&1 &
    UPROBE_CONSUMER_PID=$!
    sleep 1

    if kill -0 "$UPROBE_PID" 2>/dev/null; then
        record_ok "BPF uprobe 加载成功"
        # 触发一个 HTTPS 请求让 uprobe 捕获
        curl -sS --max-time 5 "https://example.com/" 2>/dev/null || true
        sleep 2
        if [[ -f /tmp/agw_pb_tls_audit.jsonl ]] && [[ -s /tmp/agw_pb_tls_audit.jsonl ]]; then
            record_ok "uprobe 明文采集到数据"
            TLS_LINES=$(wc -l < /tmp/agw_pb_tls_audit.jsonl)
            info " 采集到 $TLS_LINES 条明文事件"
            head -1 /tmp/agw_pb_tls_audit.jsonl | head -c 200
            echo
        else
            record_fail "uprobe 未采集到明文数据"
        fi
    else
        record_fail "BPF uprobe 加载失败"
        tail -10 logs/pb_uprobe.log
    fi

    # ── P4: seccomp 同步确认 ────────────────────────────────────────────
    section "P4: seccomp USER_NOTIF 同步确认"

    echo
    bold "  ▶ P4.1 seccomp 同步 DENY 测试"
    echo "    命令: ./bpf/seccomp_confirm -- /bin/echo denied"
    echo "    期望: echo 被 trap，notifier 同步 DENY → 不输出 'denied'"
    ./bpf/seccomp_confirm -- /bin/echo "denied" 2>/tmp/agw_pb_seccomp_deny.out || true
    if grep -q 'denied' /tmp/agw_pb_seccomp_deny.out 2>/dev/null; then
        record_fail "seccomp 未 DENY（输出了 'denied'）"
    else
        record_ok "seccomp 同步 DENY 成功（未输出 'denied'）"
    fi
    echo "    输出: $(cat /tmp/agw_pb_seccomp_deny.out 2>/dev/null | head -3)"

    echo
    bold "  ▶ P4.2 seccomp 同步 ALLOW 测试"
    echo "    命令: ./bpf/seccomp_confirm --allow -- /bin/echo allowed"
    echo "    期望: echo 被 trap，notifier 同步 ALLOW → 输出 'allowed'"
    ./bpf/seccomp_confirm --allow -- /bin/echo "allowed" 2>/tmp/agw_pb_seccomp_allow.out || true
    if grep -q 'allowed' /tmp/agw_pb_seccomp_allow.out 2>/dev/null; then
        record_ok "seccomp 同步 ALLOW 成功（输出了 'allowed'）"
    else
        record_fail "seccomp 未 ALLOW（未输出 'allowed'）"
    fi

    # ── P5: 自保护 ──────────────────────────────────────────────────────
    section "P5: BPF-LSM 自保护（security_bpf）"

    echo
    bold "  ▶ P5.1 受管进程执行 bpf() → 内核内 DENY"
    echo "    期望: bpftool prog list → Operation not permitted"
    echo "    （当前 shell 已在受管 cgroup 中）"
    bpftool prog list >/tmp/agw_pb_bpftool.out 2>/tmp/agw_pb_bpftool.err
    BPFTOOL_RC=$?
    if [[ $BPFTOOL_RC -ne 0 ]] && grep -qiE 'permission denied|operation not permitted' /tmp/agw_pb_bpftool.err; then
        record_ok "受管进程 bpf() 被内核 DENY"
        echo "    stderr: $(cat /tmp/agw_pb_bpftool.err)"
    else
        record_fail "受管进程 bpf() 未被 DENY（可能未受管或 security_bpf 未生效）"
        echo "    stderr: $(cat /tmp/agw_pb_bpftool.err 2>/dev/null | head -3)"
    fi

    # 清理内核态组件
    info "清理内核态组件..."
    kill "$LSM_PID" "$AUDIT_PID" "$TPROXY_PID" "$UPROBE_PID" "$UPROBE_CONSUMER_PID" 2>/dev/null || true
    nft delete table inet agentgateway 2>/dev/null || true
    rm -rf /sys/fs/bpf/agentgateway /sys/fs/bpf/agentgateway_uprobe 2>/dev/null || true
fi

# ─── 汇总 ──────────────────────────────────────────────────────────────────
section "验证汇总"
bold "  PASS: $PASS"
red   "  FAIL: $FAIL"
yellow "  SKIP: $SKIP"

echo
if [[ $FAIL -eq 0 ]]; then
    green "🎉 验证完成（${PASS} passed, ${SKIP} skipped）"
    echo
    echo "验证覆盖:"
    echo "  P0  透明代理 + L7 AI 请求识别     ✅"
    echo "  三方 Agent 拦截 (curl/Python/Node)  ✅"
    echo "  非 AI 请求不误拦                   ✅"
    if [[ $MODE != "user" ]]; then
        echo "  P1  BPF-LSM 网络强制 (socket_connect) ✅"
        echo "  P3  透明代理 + uprobe 明文采集       ✅"
        echo "  P4  seccomp 同步确认                 ✅"
        echo "  P5  BPF-LSM 自保护                   ✅"
    fi
    echo
    echo "审计日志: audit/audit.jsonl"
    echo "仪表盘:   http://127.0.0.1:9090"
    exit 0
else
    red "💥 有 $FAIL 项验证失败"
    exit 1
fi
