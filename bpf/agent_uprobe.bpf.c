// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
// AgentGateway BPF uprobe plaintext capture (方案 B, P3).
//
// Attaches uprobes to OpenSSL SSL_write and GnuTLS gnutls_record_send to
// capture the plaintext *before* encryption (outbound AI prompts/requests).
// Unlike 方案A's LD_PRELOAD shim, uprobes live in the kernel and cannot be
// dlopen'd away by the agent.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "agent_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} audit_buf SEC(".maps");

static __always_inline int capture(const void *buf, int num, __u8 dir)
{
    struct tls_event *ev;
    __u32 len;

    if (!buf || num <= 0)
        return 0;
    len = (__u32)num;
    if (len > TLS_CAPTURE_MAX)
        len = TLS_CAPTURE_MAX;

    ev = bpf_ringbuf_reserve(&audit_buf, sizeof(*ev), 0);
    if (!ev)
        return 0;
    ev->ts_ns = bpf_ktime_get_ns();
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->tgid = bpf_get_current_pid_tgid();
    ev->cgroup_id = bpf_get_current_cgroup_id();
    ev->len = len;
    ev->dir = dir;
    bpf_probe_read_user(ev->data, len, buf);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* OpenSSL: int SSL_write(SSL *ssl, const void *buf, int num) */
SEC("uprobe//lib/x86_64-linux-gnu/libssl.so.3:SSL_write")
int BPF_UPROBE(ssl_write_enter, void *ssl, const void *buf, int num)
{
    return capture(buf, num, 0);
}

/* GnuTLS: ssize_t gnutls_record_send(session, const void *data, size_t size) */
SEC("uprobe//lib/x86_64-linux-gnu/libgnutls.so.30:gnutls_record_send")
int BPF_UPROBE(gnutls_send_enter, void *session, const void *data, int size)
{
    return capture(data, size, 0);
}
