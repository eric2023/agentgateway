// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
// AgentGateway seccomp USER_NOTIF synchronous confirmation (方案 B, P4).
//
// Wraps a command; the seccomp filter traps execve/execveat and returns
// SECCOMP_RET_USER_NOTIF. The blocked process suspends and the notifier (parent)
// receives the attempt, prints the executable path, and synchronously allows or
// denies (default: DENY with EPERM, simulating "user rejects high-risk exec").
//
// Usage: seccomp_confirm [--allow] -- <command> [args...]

#define _GNU_SOURCE
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>

static void die(const char *m) { perror(m); exit(1); }

int main(int argc, char **argv)
{
    int allow_flag = 0;
    int i = 1;
    int listener, status;
    pid_t pid;
    struct sock_fprog prog;
    struct seccomp_notif_sizes sizes;
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;

    while (i < argc && strcmp(argv[i], "--allow") == 0) {
        allow_flag = 1;
        i++;
    }
    if (i < argc && strcmp(argv[i], "--") == 0)
        i++;
    if (i >= argc) {
        fprintf(stderr, "usage: %s [--allow] -- <command> [args...]\n", argv[0]);
        return 2;
    }

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    prog.len = (unsigned short)(sizeof(filter) / sizeof(filter[0]));
    prog.filter = filter;

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        die("prctl no_new_privs (parent)");

    listener = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                            SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (listener < 0)
        die("seccomp NEW_LISTENER (needs CAP_SYS_ADMIN)");

    if (syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0)
        die("SECCOMP_GET_NOTIF_SIZES");

    pid = fork();
    if (pid == 0) {
        /* The filter (and NO_NEW_PRIVS) are inherited across fork from the
         * parent's NEW_LISTENER install — the child must NOT re-install it. */
        execvp(argv[i], &argv[i]);
        die("execvp");
    }

    req = calloc(1, sizes.seccomp_notif);
    resp = calloc(1, sizes.seccomp_notif_resp);
    printf("[seccomp-confirm] notifier ready (child pid=%d, trap execve/execveat, mode=%s)\n",
           pid, allow_flag ? "ALLOW" : "DENY");

    struct pollfd pfd = { .fd = listener, .events = POLLIN };
    for (;;) {
        int pr = poll(&pfd, 1, 1000);
        if (waitpid(pid, &status, WNOHANG) == pid)
            break; /* child exited */
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pr == 0)
            continue;

        memset(req, 0, sizes.seccomp_notif);
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        char path[256] = "(unknown)";
        if (req->data.args[0]) {
            struct iovec local = { path, sizeof(path) - 1 };
            struct iovec remote = { (void *)req->data.args[0], sizeof(path) - 1 };
            ssize_t n = process_vm_readv(req->pid, &local, 1, &remote, 1, 0);
            if (n > 0)
                path[n] = '\0';
        }

        printf("[seccomp-confirm] child %d attempted exec '%s' -> %s\n",
               req->pid, path, allow_flag ? "ALLOW" : "DENY (EPERM)");

        resp->id = req->id;
        if (allow_flag) {
            resp->error = 0;
            resp->val = 0;
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; /* re-run syscall */
        } else {
            resp->error = EPERM; /* SECCOMP_RET_ERRNO | EPERM */
            resp->val = 0;
            resp->flags = 0;
        }
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0)
            die("SECCOMP_IOCTL_NOTIF_SEND");
    }

    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
