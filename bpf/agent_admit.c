// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
// AgentGateway agent admission helper (方案 B). Run as root (via sudo).
//
// Creates the per-agent cgroup under /sys/fs/cgroup/agentgateway/agents/,
// records its identity in the pinned identity_map (keyed by cgroup id), and
// moves target PIDs into the cgroup. Once in the cgroup, the BPF-LSM program
// treats the process as managed and enforces the sandbox.
//
// Usage: agent_admit <name> <agent-id> <session-id> <app> [pid ...]
//
// Self-contained: raw bpf(2) syscalls + name_to_handle_at; no libbpf needed.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include "agent_common.h"

#ifndef __NR_bpf
#error "this toolchain lacks __NR_bpf"
#endif

#define CGROUP_ROOT "/sys/fs/cgroup/agentgateway/agents"
#define IDENTITY_MAP_PIN "/sys/fs/bpf/agentgateway/identity_map"

static int bpf_sys(enum bpf_cmd cmd, union bpf_attr *attr)
{
    return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

/* mkdir -p */
static int mkdir_p(const char *path)
{
    char tmp[512], *p;
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = 0;
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "mkdir %s: %s\n", tmp, strerror(errno));
            return -1;
        }
        *p = '/';
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir %s: %s\n", tmp, strerror(errno));
        return -1;
    }
    return 0;
}

static int cgroup_id(const char *dir, unsigned long long *out)
{
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    struct {
        struct file_handle h;
        unsigned char space[64];
    } fh;
    int mount_id = 0;

    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", dir, strerror(errno));
        return -1;
    }
    memset(&fh, 0, sizeof(fh));
    fh.h.handle_bytes = sizeof(fh.space);
    if (name_to_handle_at(fd, "", &fh.h, &mount_id, AT_EMPTY_PATH) != 0) {
        fprintf(stderr, "name_to_handle_at %s: %s\n", dir, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    *out = *(unsigned long long *)fh.h.f_handle;
    return 0;
}

static int write_identity(unsigned long long cgid, const char *agent_id,
                          const char *session_id, const char *app)
{
    int fd = -1;
    struct agent_identity id;

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (unsigned long long)IDENTITY_MAP_PIN;
    fd = bpf_sys(BPF_OBJ_GET, &attr);
    if (fd < 0) {
        fprintf(stderr, "BPF_OBJ_GET %s: %s (is agent_lsm loaded?)\n",
                IDENTITY_MAP_PIN, strerror(errno));
        return -1;
    }

    memset(&id, 0, sizeof(id));
    snprintf(id.agent_id, sizeof(id.agent_id), "%s", agent_id);
    snprintf(id.session_id, sizeof(id.session_id), "%s", session_id);
    snprintf(id.app_name, sizeof(id.app_name), "%s", app);
    id.agent_id_len = (__u32)strlen(id.agent_id);
    id.session_id_len = (__u32)strlen(id.session_id);
    id.app_len = (__u32)strlen(id.app_name);

    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (unsigned int)fd;
    attr.key = (unsigned long long)&cgid;
    attr.value = (unsigned long long)&id;
    attr.flags = BPF_ANY;
    if (bpf_sys(BPF_MAP_UPDATE_ELEM, &attr) < 0) {
        fprintf(stderr, "BPF_MAP_UPDATE_ELEM: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int move_pid(const char *cgdir, long pid)
{
    char path[768];
    char buf[32];
    int fd;

    snprintf(path, sizeof(path), "%s/cgroup.procs", cgdir);
    fd = open(path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return -1;
    }
    snprintf(buf, sizeof(buf), "%ld", pid);
    if (write(fd, buf, strlen(buf)) < 0) {
        fprintf(stderr, "write %s <- %ld: %s\n", path, pid, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    char cgdir[512];
    unsigned long long cgid = 0;
    int i;

    if (argc < 5) {
        fprintf(stderr,
                "usage: %s <name> <agent-id> <session-id> <app> [pid ...]\n",
                argv[0]);
        return 2;
    }

    snprintf(cgdir, sizeof(cgdir), "%s/%s", CGROUP_ROOT, argv[1]);
    if (mkdir_p(cgdir) != 0)
        return 1;
    if (cgroup_id(cgdir, &cgid) != 0)
        return 1;
    if (write_identity(cgid, argv[2], argv[3], argv[4]) != 0)
        return 1;

    for (i = 5; i < argc; i++) {
        long pid = atol(argv[i]);
        if (pid > 0 && move_pid(cgdir, pid) != 0)
            return 1;
    }

    printf("admitted name=%s cgroup_id=%llu agent=%s pid_args=%d\n",
           argv[1], cgid, argv[2], argc - 5);
    return 0;
}
