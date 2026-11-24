// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
// AgentGateway uprobe plaintext consumer: streams TLS plaintext events from the
// pinned uprobe ring buffer into a JSONL file (default audit/audit-tls.jsonl).
//
// Usage: agent_uprobe_consumer [output.jsonl]

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "agent_common.h"

static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s) { (void)s; g_stop = 1; }

static void json_escape(FILE *f, const char *s, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        default:
            if (c < 0x20) fprintf(f, "\\u%04x", c);
            else fputc(c, f);
        }
    }
}

static int handle_event(void *ctx, void *data, size_t len)
{
    FILE *out = ctx;
    struct tls_event *ev = data;
    struct timeval tv;
    struct tm tmv;
    char ts[64];

    if (len < sizeof(*ev))
        return 0;

    gettimeofday(&tv, NULL);
    gmtime_r(&tv.tv_sec, &tmv);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tmv);

    fprintf(out, "{\"ts\":\"%s.%06ld+00:00\",", ts, tv.tv_usec);
    fprintf(out, "\"event\":\"tls_plaintext\",");
    fprintf(out, "\"dir\":\"%s\",", ev->dir == 0 ? "write" : "read");
    fprintf(out, "\"pid\":%u,\"tgid\":%u,\"cgroup_id\":%llu,\"len\":%u,",
            ev->pid, ev->tgid, (unsigned long long)ev->cgroup_id, ev->len);
    fprintf(out, "\"data\":\"");
    json_escape(out, ev->data, ev->len);
    fprintf(out, "\"}\n");
    fflush(out);
    return 0;
}

int main(int argc, char **argv)
{
    const char *pin_path = "/sys/fs/bpf/agentgateway_uprobe/audit_buf";
    const char *out_path = argc > 1 ? argv[1] : "audit/audit-tls.jsonl";
    struct ring_buffer *rb = NULL;
    FILE *out = NULL;
    int map_fd = -1;

    for (int i = 0; i < 50; i++) {
        map_fd = bpf_obj_get(pin_path);
        if (map_fd >= 0)
            break;
        usleep(100000);
    }
    if (map_fd < 0) {
        fprintf(stderr, "bpf_obj_get(%s): %s (is agent_uprobe running as root?)\n",
                pin_path, strerror(errno));
        return 1;
    }
    out = fopen(out_path, "a");
    if (!out) {
        fprintf(stderr, "fopen(%s): %s\n", out_path, strerror(errno));
        return 1;
    }
    rb = ring_buffer__new(map_fd, handle_event, out, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new: %s\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "[uprobe-consumer] streaming %s -> %s\n", pin_path, out_path);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    while (!g_stop)
        ring_buffer__poll(rb, 200);
    ring_buffer__free(rb);
    fclose(out);
    return 0;
}
