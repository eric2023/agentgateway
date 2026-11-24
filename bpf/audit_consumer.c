// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
// AgentGateway kernel audit consumer: reads events from the pinned ring-buffer
// map and appends JSONL lines (schema-compatible with 方案 A's audit.jsonl) so
// the existing dashboard picks them up as additional events.
//
// Usage: audit_consumer [output.jsonl]  (default: audit/audit.jsonl)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "agent_common.h"

static volatile sig_atomic_t g_stop = 0;

static void on_sig(int s)
{
    (void)s;
    g_stop = 1;
}

static void json_escape(FILE *f, const char *s)
{
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        default:
            if (c < 0x20)
                fprintf(f, "\\u%04x", c);
            else
                fputc(c, f);
        }
    }
}

static const char *decision_str(__u32 d)
{
    switch (d) {
    case DEC_DENY:     return "DENY";
    case DEC_AUDIT:    return "AUDIT";
    case DEC_ASK_USER: return "ASK_USER";
    default:           return "ALLOW";
    }
}

static const char *op_str(__u32 op)
{
    switch (op) {
    case OP_SOCKET_CONNECT: return "socket_connect";
    case OP_FILE_OPEN:      return "file_open";
    case OP_BPRM_CHECK:     return "bprm_check";
    default:                return "unknown";
    }
}

/* UTC ISO8601 with microseconds (wall-clock), matching 方案 A's ts format. */
static void fmt_ts(char *buf, size_t len)
{
    struct timeval tv;
    struct tm tmv;
    gettimeofday(&tv, NULL);
    gmtime_r(&tv.tv_sec, &tmv);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tmv);
    size_t off = strlen(buf);
    snprintf(buf + off, len - off, ".%06ld+00:00", tv.tv_usec);
}

static void fmt_ipv4(__u32 host_order, char *buf, size_t len)
{
    snprintf(buf, len, "%u.%u.%u.%u",
             (host_order >> 24) & 0xff, (host_order >> 16) & 0xff,
             (host_order >> 8) & 0xff, host_order & 0xff);
}

static int handle_event(void *ctx, void *data, size_t len)
{
    FILE *out = ctx;
    struct audit_event *ev = data;
    char ts[64], ip[16] = "-";

    if (len < sizeof(*ev))
        return 0;

    struct timeval tv;
    gettimeofday(&tv, NULL);

    fmt_ts(ts, sizeof(ts));
    if (ev->op_type == OP_SOCKET_CONNECT)
        fmt_ipv4(ev->daddr, ip, sizeof(ip));

    fprintf(out, "{");
    fprintf(out, "\"ts\":\"%s\",", ts);
    fprintf(out, "\"ts_unix\":%ld.%03ld,", tv.tv_sec, tv.tv_usec / 1000);
    fprintf(out, "\"event\":\"kernel_lsm_%s\",", op_str(ev->op_type));
    fprintf(out, "\"decision\":\"%s\",", decision_str(ev->decision));
    fprintf(out, "\"op\":\"%s\",", op_str(ev->op_type));
    fprintf(out, "\"pid\":%u,\"tgid\":%u,", ev->pid, ev->tgid);
    fprintf(out, "\"cgroup_id\":%llu,", (unsigned long long)ev->cgroup_id);
    fprintf(out, "\"result\":%d,", ev->result);
    fprintf(out, "\"agent_id\":\"");
    json_escape(out, ev->agent_id);
    fprintf(out, "\",\"session_id\":\"");
    json_escape(out, ev->session_id);
    fprintf(out, "\",\"app_name\":\"");
    json_escape(out, ev->app_name);
    fprintf(out, "\",");
    if (ev->op_type == OP_SOCKET_CONNECT) {
        fprintf(out, "\"daddr\":\"%s\",\"dport\":%u,", ip, ev->dport);
    } else if (ev->path[0]) {
        fprintf(out, "\"path\":\"");
        json_escape(out, ev->path);
        fprintf(out, "\",");
    }
    fprintf(out, "\"source\":\"bpf_lsm\"}\n");
    fflush(out);
    return 0;
}

int main(int argc, char **argv)
{
    const char *pin_path = "/sys/fs/bpf/agentgateway/audit_buf";
    const char *out_path = argc > 1 ? argv[1] : "audit/audit.jsonl";
    struct ring_buffer *rb = NULL;
    FILE *out = NULL;
    int map_fd = -1;
    int err = 1;

    /* retry: the loader may still be attaching/pinning (esp. with a large
     * verifier run). Give it up to ~5s before giving up. */
    for (int attempt = 0; attempt < 50; attempt++) {
        map_fd = bpf_obj_get(pin_path);
        if (map_fd >= 0)
            break;
        usleep(100000);
    }
    if (map_fd < 0) {
        fprintf(stderr, "bpf_obj_get(%s): %s\n", pin_path, strerror(errno));
        fprintf(stderr, "is the loader (agent_lsm) running as root?\n");
        goto out;
    }

    out = fopen(out_path, "a");
    if (!out) {
        fprintf(stderr, "fopen(%s): %s\n", out_path, strerror(errno));
        goto out;
    }

    rb = ring_buffer__new(map_fd, handle_event, out, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new: %s\n", strerror(errno));
        goto out;
    }

    fprintf(stderr, "[AgentGateway] audit consumer streaming %s -> %s\n",
            pin_path, out_path);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    while (!g_stop) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && errno != EINTR) {
            fprintf(stderr, "poll: %s\n", strerror(errno));
            break;
        }
    }
    err = 0;

out:
    if (rb)
        ring_buffer__free(rb);
    if (map_fd >= 0)
        close(map_fd);
    if (out)
        fclose(out);
    return err;
}
