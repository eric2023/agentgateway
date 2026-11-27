// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
// AgentGateway BPF-LSM loader. Loads the LSM programs, attaches them to the
// `bpf` LSM, writes the default config, and pins maps to /sys/fs/bpf/agentgateway/.
//
// Requires root (CAP_BPF + CAP_SYS_ADMIN). Unprivileged BPF is disabled
// (kernel.unprivileged_bpf_disabled=2) on this host, so sudo is mandatory.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include "agent_lsm.skel.h"
#include "agent_common.h"

static const char *PIN_DIR = "/sys/fs/bpf/agentgateway";
static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static int bump_rlimit(void)
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    return setrlimit(RLIMIT_MEMLOCK, &r);
}

int main(int argc, char **argv)
{
    struct agent_lsm_bpf *skel = NULL;
    struct agent_config cfg = {0};
    __u32 key = 0;
    int err = 1;

    cfg.enable_deny_443 = 0; /* iptables/nftables REDIRECT handles :443; BPF-LSM audit only */
    cfg.audit_file_open = 1;
    cfg.audit_bprm_check = 1;
    cfg.enforce_file_write = 0; /* default off; enable via AGW_ENFORCE_FILE_WRITE=1 */
    {
        const char *allow = getenv("AGW_WRITE_ALLOW");
        if (allow)
            strncpy(cfg.write_allow_dir, allow, sizeof(cfg.write_allow_dir) - 1);
        else
            cfg.write_allow_dir[0] = 0;
    }
    if (getenv("AGW_ENFORCE_FILE_WRITE"))
        cfg.enforce_file_write = 1;

    if (bump_rlimit()) {
        fprintf(stderr, "setrlimit: %s\n", strerror(errno));
        return 1;
    }

    skel = agent_lsm_bpf__open();
    if (!skel) {
        fprintf(stderr, "open failed: %s\n", strerror(errno));
        return 1;
    }

    err = agent_lsm_bpf__load(skel);
    if (err) {
        fprintf(stderr, "load failed: %d\n", err);
        goto out;
    }

    err = bpf_map__update_elem(skel->maps.config_map, &key, sizeof(key),
                               &cfg, sizeof(cfg), BPF_ANY);
    if (err)
        fprintf(stderr, "warning: config write failed: %d\n", err);

    err = agent_lsm_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "attach failed: %d\n", err);
        goto out;
    }

    /* Remove stale pins from previous runs (killed loaders leave pins behind). */
    mkdir(PIN_DIR, 0755); /* ignore EEXIST; bpffs pin dir */
    bpf_object__unpin_maps(skel->obj, PIN_DIR);
    err = bpf_object__pin_maps(skel->obj, PIN_DIR);
    if (err)
        fprintf(stderr, "warning: pin maps failed: %d\n", err);

    /* Make pinned maps world-readable so non-root audit_consumer can open them. */
    {
        char path[256];
        const char *maps[] = {"audit_buf", "config_map", "identity_map", "rules_map"};
        for (int i = 0; i < 4; i++) {
            snprintf(path, sizeof(path), "%s/%s", PIN_DIR, maps[i]);
            chmod(path, 0666);
        }
    }

    printf("[AgentGateway] BPF-LSM loaded, maps pinned to %s\n", PIN_DIR);
    printf("[AgentGateway] hooks: lsm/socket_connect (audit :443), "
           "lsm/file_open, lsm/bprm_check\n");

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    while (!g_stop)
        pause();

    err = 0;
out:
    if (skel)
        agent_lsm_bpf__destroy(skel);
    return err;
}
