#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
# AgentGateway 方案B 一键运行脚本。
#
# 用法:
#   ./run_agentgateway.sh build                    # 编译 BPF 组件
#   ./run_agentgateway.sh deploy [full]            # 加载 BPF-LSM + 审计消费者（full=含透明代理+uprobe）
#   ./run_agentgateway.sh admit <name> <pid>       # 纳入 Agent 进程到受管 cgroup
#   ./run_agentgateway.sh verify                   # 逐项验证
#   ./run_agentgateway.sh status                   # 查看运行状态
#   ./run_agentgateway.sh stop                     # 停止并清理
set -e

cd "$(dirname "$0")"
ACTION="${1:-help}"
shift || true

log() { echo "[agentgateway] $*"; }
need_root() {
    if [[ $EUID -ne 0 ]]; then
        exec sudo "$0" "$ACTION" "$@"
    fi
}

do_build() {
    log "编译 BPF 组件（make -C bpf all）"
    make -C bpf all
    log "编译完成"
}

do_deploy() {
    need_root "$@"
    mkdir -p logs

    # 1. CA（首次）
    if [[ ! -f certs/ca-key.pem ]]; then
        log "生成 CA"
        python3 gateway/gen_ca.py
    fi

    # 2. BPF-LSM + 审计消费者
    log "加载 BPF-LSM（socket_connect/file_open/bprm_check/bpf 内核管控）"
    ./bpf/agent_lsm > logs/agent_lsm.log 2>&1 &
    sleep 1
    ./bpf/audit_consumer audit/audit.jsonl > logs/audit_consumer.log 2>&1 &
    sleep 1
    log "已启动 BPF-LSM + 审计消费者（audit/audit.jsonl）"
    log "提示：文件写边界默认关闭，需 AGW_ENFORCE_FILE_WRITE=1 AGW_WRITE_ALLOW=<dir> 重新加载"

    # 3. 可选：透明代理 + uprobe
    if [[ "${1:-}" == "full" ]]; then
        log "启动透明代理（系统 CA + nftables redirect + SNI MITM，:8444）"
        ./bpf/setup_transparent.sh > logs/tproxy.log 2>&1 &
        sleep 1
        log "启动 uprobe 明文采集（SSL_write/gnutls_record_send）"
        ./bpf/agent_uprobe > logs/uprobe.log 2>&1 &
        sleep 1
        ./bpf/agent_uprobe_consumer audit/audit-tls.jsonl > logs/uprobe_consumer.log 2>&1 &
        sleep 1
    fi
    log "部署完成"
}

do_admit() {
    need_root "$@"
    local name="${1:-agent}"
    local pid="${2:-}"
    [[ -z "$pid" ]] && { echo "用法: $0 admit <name> <pid>"; exit 1; }
    local aid="agent-$(cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-' | head -c8)"
    local sid="session-$(cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-' | head -c8)"
    ./bpf/agent_admit "$name" "$aid" "$sid" "$name" "$pid"
    log "已纳入进程 $pid 到受管 cgroup（name=$name, agent_id=$aid）"
}

do_verify() {
    need_root "$@"
    log "P1 验证：受管进程直连 443 → 内核内 DENY"
    bash bpf/verify_p1.sh || true
    log "P4 验证：seccomp USER_NOTIF 同步确认"
    ./bpf/seccomp_confirm -- /bin/echo "denied" || true
    ./bpf/seccomp_confirm --allow -- /bin/echo "allowed"
    log "验证完成"
}

do_status() {
    echo "=== 运行中的组件 ==="
    pgrep -af 'bpf/agent_lsm|bpf/audit_consumer|bpf/agent_uprobe|gateway/transparent_proxy' || echo "(无)"
    echo "=== nftables 规则 ==="
    sudo nft list table inet agentgateway 2>/dev/null | head -6 || echo "(无)"
    echo "=== pinned maps ==="
    ls -d /sys/fs/bpf/agentgateway /sys/fs/bpf/agentgateway_uprobe 2>/dev/null || echo "(无)"
}

do_stop() {
    need_root "$@"
    pkill -f 'bpf/agent_lsm' 2>/dev/null || true
    pkill -f 'bpf/audit_consumer' 2>/dev/null || true
    pkill -f 'bpf/agent_uprobe' 2>/dev/null || true
    pkill -f 'bpf/agent_uprobe_consumer' 2>/dev/null || true
    pkill -f 'gateway/transparent_proxy.py' 2>/dev/null || true
    nft delete table inet agentgateway 2>/dev/null || true
    rm -rf /sys/fs/bpf/agentgateway /sys/fs/bpf/agentgateway_uprobe 2>/dev/null || true
    log "已停止并清理"
}

case "$ACTION" in
    build)  do_build "$@" ;;
    deploy) do_deploy "$@" ;;
    admit)  do_admit "$@" ;;
    verify) do_verify "$@" ;;
    status) do_status ;;
    stop)   do_stop "$@" ;;
    *)
        echo "用法: $0 {build|deploy [full]|admit <name> <pid>|verify|status|stop}"
        exit 1 ;;
esac
