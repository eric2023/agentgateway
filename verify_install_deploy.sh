#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
# AgentGateway 自动化安装部署验证脚本
#
# 验证范围（按可用权限分层）:
#   L1  DEB 包结构与完整性（免 root）
#   L2  用户态网关 + 仪表盘部署（方案 A，免 root）
#   L3  BPF 编译产物完整性（免 root，加载需 root 跳过）
#   L4  一键脚本 dry-run（免 root）
#
# 用法: ./verify_install_deploy.sh [stop]
#   无参数 = 运行全部验证；stop = 仅清理验证残留进程

set -uo pipefail
cd "$(dirname "$0")"

PROJECT_DIR="$(pwd)"
PASS=0; FAIL=0; SKIP=0
GATEWAY_PID=""; DASHBOARD_PID=""

red()    { printf "\033[31m%s\033[0m\n" "$*"; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
bold()   { printf "\033[1m%s\033[0m\n" "$*"; }

ok()   { green "  ✅ PASS: $*"; PASS=$((PASS+1)); }
fail() { red   "  ❌ FAIL: $*"; FAIL=$((FAIL+1)); }
skip() { yellow "  ⏭  SKIP: $*"; SKIP=$((SKIP+1)); }
section() { printf "\n\033[1;36m═══ %s ═══\033[0m\n" "$*"; }

PYTHON="$(command -v python3 || true)"
[[ -z "$PYTHON" ]] && PYTHON="/home/ut000520@uos/.pyenv/shims/python3"

cleanup() {
    [[ -n "$GATEWAY_PID" ]]   && kill "$GATEWAY_PID"   2>/dev/null || true
    [[ -n "$DASHBOARD_PID" ]] && kill "$DASHBOARD_PID" 2>/dev/null || true
    # restore gsettings if gateway set manual proxy
    gsettings set org.gnome.system.proxy mode 'auto' 2>/dev/null || true
    rm -f /tmp/agw_verify_*.txt 2>/dev/null || true
}

if [[ "${1:-}" == "stop" ]]; then
    cleanup
    echo "[verify] cleaned up"
    exit 0
fi
trap cleanup EXIT INT TERM

section "L1: DEB 包结构与完整性"

DEB="dist/agentgateway-bpf_1.0.0_amd64.deb"

if [[ ! -f "$DEB" ]]; then
    fail "DEB 包不存在: $DEB"
else
    ok "DEB 包存在: $DEB ($(du -h "$DEB" | cut -f1))"

    # L1.1 control 元数据（dpkg-deb -f 逐字段提取，避免 -I 的前导空格问题）
    if dpkg-deb -f "$DEB" >/tmp/agw_verify_ctrl.txt 2>&1; then
        ok "dpkg-deb -f 元数据可读"
        grep -q 'Package: agentgateway-bpf'      /tmp/agw_verify_ctrl.txt && ok "Package 字段正确"      || fail "Package 字段缺失"
        grep -q 'Version: 1.0.0'                 /tmp/agw_verify_ctrl.txt && ok "Version 字段正确"      || fail "Version 字段缺失"
        grep -q 'Architecture: amd64'            /tmp/agw_verify_ctrl.txt && ok "Architecture 字段正确" || fail "Architecture 字段缺失"
        grep -q 'libbpf1'                        /tmp/agw_verify_ctrl.txt && ok "Depends 含 libbpf1"    || fail "Depends 缺 libbpf1"
        grep -q 'python3'                        /tmp/agw_verify_ctrl.txt && ok "Depends 含 python3"   || fail "Depends 缺 python3"
        grep -q 'systemd'                        /tmp/agw_verify_ctrl.txt && ok "Depends 含 systemd"   || fail "Depends 缺 systemd"
    else
        fail "dpkg-deb -f 元数据不可读"
    fi

    # L1.2 control 维护脚本（dpkg-deb -I 列出 postinst/prerm 等脚本）
    if dpkg-deb -I "$DEB" 2>/dev/null | grep -q 'postinst'; then
        ok "postinst 维护脚本存在"
    else
        fail "postinst 维护脚本缺失"
    fi
    if dpkg-deb -I "$DEB" 2>/dev/null | grep -q 'prerm'; then
        ok "prerm 维护脚本存在"
    else
        fail "prerm 维护脚本缺失"
    fi
    dpkg-deb -e "$DEB" /tmp/agw_verify_debian/ 2>/dev/null
    [[ -x /tmp/agw_verify_debian/postinst ]] && ok "postinst 可执行" || fail "postinst 不可执行"
    [[ -x /tmp/agw_verify_debian/prerm ]]    && ok "prerm 可执行"    || fail "prerm 不可执行"
    grep -q 'update-ca-certificates' /tmp/agw_verify_debian/postinst 2>/dev/null && ok "postinst 含 CA 注册" || fail "postinst 缺 CA 注册"
    grep -q 'systemctl enable'        /tmp/agw_verify_debian/postinst 2>/dev/null && ok "postinst 含 systemd enable" || fail "postinst 缺 systemd enable"
    grep -q 'systemctl stop'          /tmp/agw_verify_debian/prerm    2>/dev/null && ok "prerm 含 systemd stop" || fail "prerm 缺 systemd stop"

    # L1.3 内容清单
    dpkg-deb -c "$DEB" >/tmp/agw_verify_contents.txt 2>&1
    declare -a REQUIRED_PATHS=(
        "usr/lib/agentgateway/bpf/agent_lsm"
        "usr/lib/agentgateway/bpf/audit_consumer"
        "usr/lib/agentgateway/bpf/agent_admit"
        "usr/lib/agentgateway/bpf/agent_uprobe"
        "usr/lib/agentgateway/bpf/seccomp_confirm"
        "usr/lib/agentgateway/bpf/setup_transparent.sh"
        "usr/lib/agentgateway/bpf/agent_lsm.bpf.o"
        "usr/lib/agentgateway/bpf/vmlinux.h"
        "usr/lib/agentgateway/gateway/agentgatewayd.py"
        "usr/lib/agentgateway/gateway/transparent_proxy.py"
        "usr/lib/agentgateway/gateway/gen_ca.py"
        "usr/lib/agentgateway/certs/ca-cert.pem"
        "usr/lib/agentgateway/run_agentgateway.sh"
        "etc/systemd/system/agentgateway-lsm.service"
        "etc/systemd/system/agentgateway-audit.service"
        "etc/systemd/system/agentgateway-tproxy.service"
        "etc/systemd/system/agentgateway-uprobe.service"
        "etc/systemd/system/agentgateway-uprobe-consumer.service"
    )
    for p in "${REQUIRED_PATHS[@]}"; do
        if grep -q "\\./$p$" /tmp/agw_verify_contents.txt; then
            ok "包含 $p"
        else
            fail "缺少 $p"
        fi
    done

    # L1.4 关键二进制可执行权限
    for p in agent_lsm audit_consumer agent_admit agent_uprobe seccomp_confirm; do
        if grep -q "rwxr-xr-x.*\\./usr/lib/agentgateway/bpf/$p$" /tmp/agw_verify_contents.txt; then
            ok "$p 权限 755"
        else
            fail "$p 权限非 755"
        fi
    done

    # L1.5 CA 私钥绝不打包
    if grep -q 'ca-key.pem' /tmp/agw_verify_contents.txt; then
        fail "CA 私钥被打包进 DEB（安全风险）"
    else
        ok "CA 私钥未打包（安全）"
    fi

    # L1.6 systemd 单元内容
    mkdir -p /tmp/agw_verify_extract
    dpkg-deb -x "$DEB" /tmp/agw_verify_extract/ 2>/dev/null
    for svc in agentgateway-lsm agentgateway-audit agentgateway-tproxy agentgateway-uprobe agentgateway-uprobe-consumer; do
        f="/tmp/agw_verify_extract/etc/systemd/system/$svc.service"
        if [[ -f "$f" ]]; then
            grep -q 'ExecStart=' "$f" && ok "$svc.service 含 ExecStart" || fail "$svc.service 缺 ExecStart"
            grep -q 'WantedBy=multi-user.target' "$f" && ok "$svc.service 含 WantedBy" || fail "$svc.service 缺 WantedBy"
        else
            fail "$svc.service 不存在"
        fi
    done
fi

# ─── L2: 用户态网关 + 仪表盘 ───────────────────────────────────────────────
section "L2: 用户态网关 + 仪表盘部署（方案 A）"

# L2.1 CA 证书
if [[ -f certs/ca-cert.pem && -f certs/ca-key.pem ]]; then
    ok "CA 证书 + 私钥存在"
    if "$PYTHON" -c "
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import sys
with open('certs/ca-cert.pem','rb') as f:
    cert = x509.load_pem_x509_certificate(f.read())
cn = cert.subject.rfc4514_string()
print('CA subject:', cn)
sys.exit(0 if 'AgentGateway' in cn else 1)
" 2>/dev/null; then
        ok "CA 证书可解析，CN 含 AgentGateway"
    else
        fail "CA 证书解析失败"
    fi
else
    fail "CA 证书/私钥缺失"
fi

# L2.2 Python 依赖
if "$PYTHON" -c "import cryptography; print('cryptography', cryptography.__version__)" 2>/dev/null; then
    ok "cryptography 可导入"
else
    fail "cryptography 不可导入"
fi
if "$PYTHON" -c "import ssl, socket, json, http.server, urllib.request; print('stdlib OK')" 2>/dev/null; then
    ok "Python 标准库可用"
else
    fail "Python 标准库异常"
fi

# L2.3 网关启动（清理残留动态证书，避免 cert/key 不匹配）
rm -f certs/dyn-*.pem 2>/dev/null
echo "  启动网关..."
"$PYTHON" gateway/agentgatewayd.py >>logs/verify_gateway.log 2>&1 &
GATEWAY_PID=$!
sleep 3

if kill -0 "$GATEWAY_PID" 2>/dev/null; then
    ok "网关进程存活 (pid=$GATEWAY_PID)"
else
    fail "网关进程已退出"
    tail -20 logs/verify_gateway.log 2>/dev/null
fi

# L2.4 端口监听
if ss -tlnp 2>/dev/null | grep -q ':8443'; then
    ok "网关监听 :8443"
else
    fail "网关未监听 :8443"
fi

# L2.5 仪表盘启动
echo "  启动仪表盘..."
"$PYTHON" dashboard/dashboard.py >>logs/verify_dashboard.log 2>&1 &
DASHBOARD_PID=$!
sleep 2

if kill -0 "$DASHBOARD_PID" 2>/dev/null; then
    ok "仪表盘进程存活 (pid=$DASHBOARD_PID)"
else
    fail "仪表盘进程已退出"
    tail -20 logs/verify_dashboard.log 2>/dev/null
fi

if ss -tlnp 2>/dev/null | grep -q ':9090'; then
    ok "仪表盘监听 :9090"
else
    fail "仪表盘未监听 :9090"
fi

# L2.6 仪表盘 HTTP 响应
HTTP_CODE=$(curl -s -o /tmp/agw_verify_dash.html -w '%{http_code}' --max-time 5 http://127.0.0.1:9090/ 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
    ok "仪表盘 HTTP 200"
    if grep -qi 'AgentGateway\|agentgateway\|dashboard' /tmp/agw_verify_dash.html 2>/dev/null; then
        ok "仪表盘 HTML 含 AgentGateway 内容"
    else
        fail "仪表盘 HTML 内容异常"
    fi
else
    fail "仪表盘 HTTP 响应码: $HTTP_CODE"
fi

# L2.7 AI 请求拦截验证（通过 CONNECT 代理）
if kill -0 "$GATEWAY_PID" 2>/dev/null; then
    # 记录当前审计日志行数作为标记（系统代理流量会持续写入，不能清空）
    AUDIT_MARKER=$(wc -l < audit/audit.jsonl 2>/dev/null || echo 0)
    # 通过代理发送模拟 AI 请求（无需真实上游，网关审计后转发即失败也无所谓）
    curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
        -x "http://127.0.0.1:8443" \
        --cacert certs/ca-cert.pem \
        -X POST "https://api.openai.com/v1/chat/completions" \
        -H 'Content-Type: application/json' \
        -H 'Authorization: Bearer sk-verify-test-key' \
        -d '{"model":"gpt-4","messages":[{"role":"user","content":"verify"}]}' \
        2>/dev/null || true
    sleep 2
    # 只检查标记行之后的新增审计记录
    NEW_AUDIT=$(tail -n +"$((AUDIT_MARKER + 1))" audit/audit.jsonl 2>/dev/null)
    if echo "$NEW_AUDIT" | grep -q 'ai_request_audited'; then
        ok "AI 请求被审计记录（audit.jsonl 含 ai_request_audited）"
        if echo "$NEW_AUDIT" | grep -q '"host": "api.openai.com"\|"host":"api.openai.com"'; then
            ok "审计记录 host=api.openai.com"
        else
            fail "审计记录 host 不匹配"
        fi
        if echo "$NEW_AUDIT" | grep -q '"decision": "AUDIT"\|"decision":"AUDIT"'; then
            ok "审计 decision=AUDIT（非阻断）"
        else
            fail "审计 decision 非 AUDIT"
        fi
    else
        fail "AI 请求未被审计"
        echo "$NEW_AUDIT" | head -3
    fi
fi

# ─── L3: BPF 编译产物 ─────────────────────────────────────────────────────
section "L3: BPF 编译产物完整性"

declare -a BPF_BINS=(bpf/agent_lsm bpf/audit_consumer bpf/agent_admit bpf/agent_landlock
                     bpf/agent_uprobe bpf/agent_uprobe_consumer bpf/seccomp_confirm bpf/cgroupid)
for b in "${BPF_BINS[@]}"; do
    if [[ -x "$b" ]]; then
        ok "$b 存在且可执行"
    else
        fail "$b 缺失或不可执行"
    fi
done

declare -a BPF_OBJS=(bpf/agent_lsm.bpf.o bpf/agent_uprobe.bpf.o bpf/vmlinux.h)
for o in "${BPF_OBJS[@]}"; do
    if [[ -f "$o" ]]; then
        ok "$o 存在 ($(du -h "$o" | cut -f1))"
    else
        fail "$o 缺失"
    fi
done

# L3.1 BPF ELF 校验
if file bpf/agent_lsm.bpf.o 2>/dev/null | grep -q 'ELF.*BPF'; then
    ok "agent_lsm.bpf.o 是 BPF ELF 对象"
else
    fail "agent_lsm.bpf.o 非 BPF ELF"
fi

# L3.2 loader 二进制 ELF
if file bpf/agent_lsm 2>/dev/null | grep -q 'ELF.*x86-64'; then
    ok "agent_lsm loader 是 x86-64 ELF"
else
    fail "agent_lsm loader 非可执行 ELF"
fi

# L3.3 BPF-LSM 加载需 root — 跳过
if [[ $EUID -ne 0 ]]; then
    skip "BPF-LSM 加载验证（需 root: sudo ./bpf/agent_lsm）"
    skip "P1 网络强制验证（需 root: sudo bash bpf/verify_p1.sh）"
    skip "P3 透明代理 nftables 验证（需 root）"
    skip "P5 自保护验证（需 root）"
else
    # 有 root：执行真实 BPF 加载
    echo "  以 root 身份加载 BPF-LSM..."
    rm -rf /sys/fs/bpf/agentgateway 2>/dev/null || true
    ./bpf/agent_lsm >>logs/verify_lsm.log 2>&1 &
    LSM_PID=$!
    sleep 2
    if kill -0 "$LSM_PID" 2>/dev/null; then
        ok "BPF-LSM 加载成功 (pid=$LSM_PID)"
        if [[ -d /sys/fs/bpf/agentgateway ]]; then
            ok "BPF maps pinned 到 /sys/fs/bpf/agentgateway"
        else
            fail "BPF maps 未 pinned"
        fi
        ./bpf/audit_consumer /tmp/agw_verify_audit.jsonl >>logs/verify_audit.log 2>&1 &
        AUDIT_PID=$!
        sleep 1
        kill -0 "$AUDIT_PID" 2>/dev/null && ok "审计消费者启动" || fail "审计消费者启动失败"
        kill "$LSM_PID" "$AUDIT_PID" 2>/dev/null || true
        wait "$LSM_PID" "$AUDIT_PID" 2>/dev/null || true
    else
        fail "BPF-LSM 加载失败"
        tail -20 logs/verify_lsm.log 2>/dev/null
    fi
fi

# ─── L4: 一键脚本 dry-run ─────────────────────────────────────────────────
section "L4: 一键脚本检查"

# L4.1 run_agentgateway.sh 语法
if bash -n run_agentgateway.sh 2>/dev/null; then
    ok "run_agentgateway.sh 语法正确"
else
    fail "run_agentgateway.sh 语法错误"
fi

# L4.2 run_agentgateway.sh help
HELP_OUT=$(bash run_agentgateway.sh help 2>&1 || true)
if echo "$HELP_OUT" | grep -q 'build\|deploy\|verify\|status\|stop'; then
    ok "run_agentgateway.sh help 输出用法"
else
    fail "run_agentgateway.sh help 无用法输出"
fi

# L4.3 start.sh 语法
if bash -n start.sh 2>/dev/null; then
    ok "start.sh 语法正确"
else
    fail "start.sh 语法错误"
fi

# L4.4 start.sh status（检查 start.sh 能否正确报告状态）
# 网关由本脚本直接启动（非 start.sh），所以先写 pidfile 让 status 能读到
echo "$GATEWAY_PID" > logs/gateway.pid 2>/dev/null || true
echo "$DASHBOARD_PID" > logs/dashboard.pid 2>/dev/null || true
STATUS_OUT=$(bash start.sh status 2>&1 || true)
if echo "$STATUS_OUT" | grep -q 'running'; then
    ok "start.sh status 检测到运行中的组件"
else
    fail "start.sh status 未检测到运行组件"
fi

# L4.5 build_deb.sh 语法
if bash -n packaging/build_deb.sh 2>/dev/null; then
    ok "build_deb.sh 语法正确"
else
    fail "build_deb.sh 语法错误"
fi

# L4.6 trustexec.sh 语法
if bash -n trustexec.sh 2>/dev/null; then
    ok "trustexec.sh 语法正确"
else
    fail "trustexec.sh 语法错误"
fi

# L4.7 setup_transparent.sh 语法
if bash -n bpf/setup_transparent.sh 2>/dev/null; then
    ok "setup_transparent.sh 语法正确"
else
    fail "setup_transparent.sh 语法错误"
fi

# ─── L5: 安装模拟（sandbox extract）────────────────────────────────────────
section "L5: 安装模拟（sandbox 解包验证）"

SANDBOX=/tmp/agw_verify_sandbox
rm -rf "$SANDBOX" 2>/dev/null
mkdir -p "$SANDBOX"

if dpkg-deb -x "$DEB" "$SANDBOX/" 2>/dev/null; then
    ok "DEB 包可完整解包到 sandbox"

    # 验证关键文件在 sandbox 中可读
    for f in usr/lib/agentgateway/bpf/agent_lsm \
             usr/lib/agentgateway/gateway/agentgatewayd.py \
             usr/lib/agentgateway/certs/ca-cert.pem \
             usr/lib/agentgateway/run_agentgateway.sh; do
        if [[ -f "$SANDBOX/$f" ]]; then
            ok "sandbox 含 $f"
        else
            fail "sandbox 缺 $f"
        fi
    done

    # 验证 sandbox 中的 agentgatewayd.py 可导入（语法检查）
    if "$PYTHON" -c "
import py_compile, sys
try:
    py_compile.compile('$SANDBOX/usr/lib/agentgateway/gateway/agentgatewayd.py', doraise=True)
    py_compile.compile('$SANDBOX/usr/lib/agentgateway/gateway/transparent_proxy.py', doraise=True)
    py_compile.compile('$SANDBOX/usr/lib/agentgateway/gateway/gen_ca.py', doraise=True)
except py_compile.PyCompileError as e:
    print(e, file=sys.stderr)
    sys.exit(1)
" 2>/dev/null; then
        ok "sandbox 中 Python 模块语法正确"
    else
        fail "sandbox 中 Python 模块语法错误"
    fi

    # 验证 sandbox 中二进制可执行
    if "$SANDBOX/usr/lib/agentgateway/bpf/cgroupid" 2>/dev/null || [[ $? -ne 126 ]]; then
        ok "sandbox 中 cgroupid 可执行（非权限错误）"
    else
        fail "sandbox 中 cgroupid 不可执行"
    fi
else
    fail "DEB 包解包失败"
fi

rm -rf "$SANDBOX" /tmp/agw_verify_extract /tmp/agw_verify_debian 2>/dev/null || true

# ─── 汇总 ──────────────────────────────────────────────────────────────────
section "验证汇总"
bold "  PASS: $PASS"
red   "  FAIL: $FAIL"
yellow "  SKIP: $SKIP"

echo
if [[ $FAIL -eq 0 ]]; then
    green "🎉 全部验证通过（${PASS} passed, ${SKIP} skipped）"
    exit 0
else
    red "💥 有 $FAIL 项验证失败"
    exit 1
fi
