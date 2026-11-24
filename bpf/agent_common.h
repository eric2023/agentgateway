// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
// Shared struct/enum definitions between the BPF-LSM program (clang -target bpf)
// and the user-space loader/consumer (gcc). Keep field layout identical.

#ifndef AGW_AGENT_COMMON_H
#define AGW_AGENT_COMMON_H

/* Userspace: __u32/__u64 come from <linux/types.h>. BPF side (clang -target bpf
 * defines __bpf__): vmlinux.h already provides them, and <linux/types.h> would
 * pull the multiarch <asm/types.h> that the BPF target cannot resolve. */
#ifndef __bpf__
#include <linux/types.h>
#endif

/* decision codes */
enum agw_decision {
    DEC_ALLOW    = 0,
    DEC_DENY     = 1,
    DEC_AUDIT    = 2,
    DEC_ASK_USER = 3,
};

/* operation (hook) types */
enum agw_op {
    OP_FILE_OPEN      = 1,
    OP_SOCKET_CONNECT = 2,
    OP_BPRM_CHECK     = 3,
};

/* identity map value: cgroup_id -> agent identity (written by trustexec helper) */
struct agent_identity {
    __u32 agent_id_len;
    __u32 session_id_len;
    __u32 app_len;
    __u8  pad[4];
    char  agent_id[64];
    char  session_id[64];
    char  app_name[64];
};

/* fine-grained rule map (reserved; v1 uses config defaults) */
struct rule_key {
    __u32 op_type;
    __u32 object_hash;
};

struct rule_value {
    __u32 decision;
    __u32 priority;
    __u64 ttl_ns;
    __u64 hit_count;
};

/* runtime config (config_map[0]) */
struct agent_config {
    __u32 enable_deny_443;   /* deny direct non-loopback :443 for managed agents */
    __u32 audit_file_open;   /* emit audit on managed file open */
    __u32 audit_bprm_check;  /* emit audit on managed exec */
};

/* ring-buffer audit event (audit_buf) */
#define AGW_PATH_MAXLEN 256

struct audit_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    __u64 cgroup_id;
    __u32 op_type;
    __u32 decision;
    __s32 result;            /* 0 allow, negative errno on deny */
    __u16 dport;
    __u32 daddr;             /* ipv4, host byte order */
    char  agent_id[64];
    char  session_id[64];
    char  app_name[64];
    char  path[AGW_PATH_MAXLEN];
};

#endif /* AGW_AGENT_COMMON_H */
