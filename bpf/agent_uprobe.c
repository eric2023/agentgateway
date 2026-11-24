// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
// AgentGateway uprobe loader: attaches SSL_write/gnutls_record_send uprobes and
// pins the ring buffer to /sys/fs/bpf/agentgateway_uprobe/.
//
// Requires root (CAP_BPF + CAP_SYS_ADMIN).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include "agent_uprobe.skel.h"

static const char *PIN_DIR = "/sys/fs/bpf/agentgateway_uprobe";
static volatile sig_atomic_t g_stop = 0;

static void on_sig(int s) { (void)s; g_stop = 1; }

int main(void)
{
    struct agent_uprobe_bpf *skel;
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    int err = 1;

    setrlimit(RLIMIT_MEMLOCK, &rl);

    skel = agent_uprobe_bpf__open();
    if (!skel) {
        fprintf(stderr, "open: %s\n", strerror(errno));
        return 1;
    }
    if (agent_uprobe_bpf__load(skel)) {
        fprintf(stderr, "load failed\n");
        goto out;
    }
    if (agent_uprobe_bpf__attach(skel)) {
        fprintf(stderr, "attach failed (is libssl.so.3 / libgnutls.so.30 present?)\n");
        goto out;
    }
    mkdir(PIN_DIR, 0755);
    bpf_object__pin_maps(skel->obj, PIN_DIR);

    printf("[uprobe] loaded, ringbuf pinned to %s/audit_buf\n", PIN_DIR);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    while (!g_stop)
        pause();
    err = 0;
out:
    agent_uprobe_bpf__destroy(skel);
    return err;
}
