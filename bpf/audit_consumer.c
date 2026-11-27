// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
// AgentGateway kernel audit consumer: reads events from the pinned ring-buffer
// map. Two sink modes:
//   --sqlite <db>   write into the Rust proxy's SQLite audit.db (bpf_events
//                   table, WAL mode — unified with 方案C's events table)
//   [jsonl_path]    append JSONL lines (default audit/audit.jsonl, 方案A/C compat)
//
// Usage:
//   audit_consumer --sqlite audit/audit.db
//   audit_consumer [audit/audit.jsonl]
//
// Requires root only to open the pinned BPF map; the SQLite file is opened
// with the caller's privileges. libsqlite3-dev is the only extra dependency.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sqlite3.h>
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
    case OP_BPF:            return "bpf";
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

/* SQLite sink: insert a BPF audit event into the bpf_events table (shared with
 * the Rust proxy's audit.db). Schema mirrors the JSONL fields; the table is
 * created with IF NOT EXISTS so it coexists with the Rust-written events table.
 * NB: prefixed AGW_ to avoid collision with sqlite3.h macros SQLITE_SCHEMA /
 * SQLITE_INSERT (defined as result-code integers in sqlite3.h). */
static const char *AGW_SQL_SCHEMA =
    "CREATE TABLE IF NOT EXISTS bpf_events ("
    "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  ts          TEXT NOT NULL,"
    "  ts_unix     REAL NOT NULL,"
    "  event       TEXT NOT NULL,"
    "  decision    TEXT,"
    "  op          TEXT,"
    "  pid         INTEGER,"
    "  tgid        INTEGER,"
    "  cgroup_id   INTEGER,"
    "  result      INTEGER,"
    "  agent_id    TEXT,"
    "  session_id  TEXT,"
    "  app_name    TEXT,"
    "  daddr       TEXT,"
    "  dport       INTEGER,"
    "  path        TEXT,"
    "  source      TEXT"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_bpf_ts    ON bpf_events(ts_unix DESC);"
    "CREATE INDEX IF NOT EXISTS idx_bpf_agent ON bpf_events(agent_id);"
    "CREATE INDEX IF NOT EXISTS idx_bpf_event ON bpf_events(event);";

static const char *AGW_SQL_INSERT =
    "INSERT INTO bpf_events "
    "(ts,ts_unix,event,decision,op,pid,tgid,cgroup_id,result,"
    " agent_id,session_id,app_name,daddr,dport,path,source) "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

struct sqlite_sink {
    sqlite3 *db;
    sqlite3_stmt *stmt;
};

static int sqlite_sink_open(struct sqlite_sink *s, const char *db_path)
{
    if (sqlite3_open(db_path, &s->db) != SQLITE_OK) {
        fprintf(stderr, "sqlite3_open(%s): %s\n", db_path, sqlite3_errmsg(s->db));
        return -1;
    }
    sqlite3_busy_timeout(s->db, 5000);
    if (sqlite3_exec(s->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL) != SQLITE_OK)
        fprintf(stderr, "warning: WAL mode: %s\n", sqlite3_errmsg(s->db));
    if (sqlite3_exec(s->db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL) != SQLITE_OK)
        fprintf(stderr, "warning: synchronous: %s\n", sqlite3_errmsg(s->db));
    if (sqlite3_exec(s->db, AGW_SQL_SCHEMA, NULL, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "sqlite schema: %s\n", sqlite3_errmsg(s->db));
        sqlite3_close(s->db);
        return -1;
    }
    if (sqlite3_prepare_v2(s->db, AGW_SQL_INSERT, -1, &s->stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "sqlite prepare: %s\n", sqlite3_errmsg(s->db));
        sqlite3_close(s->db);
        return -1;
    }
    return 0;
}

static void sqlite_sink_close(struct sqlite_sink *s)
{
    if (s->stmt)
        sqlite3_finalize(s->stmt);
    if (s->db)
        sqlite3_close(s->db);
}

/* Generic event formatter: fills ts/ts_unix and op/decision strings. Shared by
 * both the JSONL and SQLite sinks so field semantics stay identical. */
static int format_event(struct audit_event *ev, char *ts, size_t ts_len,
                        char *ip, size_t ip_len, double *ts_unix_out,
                        const char **op, const char **decision)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    fmt_ts(ts, ts_len);
    *ts_unix_out = (double)tv.tv_sec + (double)tv.tv_usec / 1000.0;
    ip[0] = '-';
    ip[1] = '\0';
    if (ev->op_type == OP_SOCKET_CONNECT)
        fmt_ipv4(ev->daddr, ip, ip_len);
    *op = op_str(ev->op_type);
    *decision = decision_str(ev->decision);
    return 0;
}

static int handle_event_jsonl(void *ctx, void *data, size_t len)
{
    FILE *out = ctx;
    struct audit_event *ev = data;
    char ts[64], ip[16];
    double ts_unix;
    const char *op, *decision;

    if (len < sizeof(*ev))
        return 0;

    format_event(ev, ts, sizeof(ts), ip, sizeof(ip), &ts_unix, &op, &decision);

    fprintf(out, "{");
    fprintf(out, "\"ts\":\"%s\",", ts);
    fprintf(out, "\"ts_unix\":%.3f,", ts_unix);
    fprintf(out, "\"event\":\"kernel_lsm_%s\",", op);
    fprintf(out, "\"decision\":\"%s\",", decision);
    fprintf(out, "\"op\":\"%s\",", op);
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

static int handle_event_sqlite(void *ctx, void *data, size_t len)
{
    struct sqlite_sink *s = ctx;
    struct audit_event *ev = data;
    char ts[64], ip[16];
    double ts_unix;
    const char *op, *decision;
    int rc;

    if (len < sizeof(*ev))
        return 0;

    format_event(ev, ts, sizeof(ts), ip, sizeof(ip), &ts_unix, &op, &decision);

    sqlite3_reset(s->stmt);
    sqlite3_bind_text(s->stmt, 1,  ts,       -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(s->stmt, 2, ts_unix);
    /* event column: "kernel_lsm_<op>" to mirror the JSONL event name */
    char event_name[48];
    snprintf(event_name, sizeof(event_name), "kernel_lsm_%s", op);
    sqlite3_bind_text(s->stmt, 3,  event_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s->stmt, 4,  decision, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s->stmt, 5,  op,       -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (s->stmt, 6,  (int)ev->pid);
    sqlite3_bind_int (s->stmt, 7,  (int)ev->tgid);
    sqlite3_bind_int64(s->stmt, 8, (sqlite3_int64)ev->cgroup_id);
    sqlite3_bind_int (s->stmt, 9,  ev->result);
    sqlite3_bind_text(s->stmt, 10, ev->agent_id[0]   ? ev->agent_id   : NULL, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s->stmt, 11, ev->session_id[0] ? ev->session_id : NULL, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s->stmt, 12, ev->app_name[0]   ? ev->app_name   : NULL, -1, SQLITE_TRANSIENT);
    if (ev->op_type == OP_SOCKET_CONNECT) {
        sqlite3_bind_text(s->stmt, 13, ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int (s->stmt, 14, ev->dport);
        sqlite3_bind_text(s->stmt, 15, NULL, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_text(s->stmt, 13, NULL, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int (s->stmt, 14, 0);
        sqlite3_bind_text(s->stmt, 15, ev->path[0] ? ev->path : NULL, -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_text(s->stmt, 16, "bpf_lsm", -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(s->stmt);
    if (rc != SQLITE_DONE)
        fprintf(stderr, "sqlite insert: %s\n", sqlite3_errmsg(s->db));
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [--sqlite <db>] [jsonl_path]\n"
        "  --sqlite <db>   write BPF audit events into SQLite (bpf_events table)\n"
        "  jsonl_path      also/instead append JSONL (default audit/audit.jsonl)\n"
        "If --sqlite is given without a jsonl_path, only SQLite is written.\n",
        prog);
}

int main(int argc, char **argv)
{
    const char *pin_path = "/sys/fs/bpf/agentgateway/audit_buf";
    const char *sqlite_path = NULL;
    const char *jsonl_path = "audit/audit.jsonl";
    int jsonl_explicit = 0;
    struct ring_buffer *rb = NULL;
    FILE *out = NULL;
    struct sqlite_sink sink = {0};
    int use_sqlite = 0;
    int map_fd = -1;
    int err = 1;

    /* Parse args: --sqlite <db> [jsonl_path]  |  [jsonl_path] */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--sqlite") == 0) {
            if (++i >= argc) { usage(argv[0]); return 2; }
            sqlite_path = argv[i];
            use_sqlite = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (!jsonl_explicit) {
            jsonl_path = argv[i];
            jsonl_explicit = 1;
        }
    }

    /* If --sqlite given without an explicit jsonl path, skip JSONL. */
    if (use_sqlite && !jsonl_explicit)
        jsonl_path = NULL;

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

    if (jsonl_path) {
        out = fopen(jsonl_path, "a");
        if (!out) {
            fprintf(stderr, "fopen(%s): %s\n", jsonl_path, strerror(errno));
            goto out;
        }
    }

    if (use_sqlite) {
        if (sqlite_sink_open(&sink, sqlite_path) != 0)
            goto out;
    }

    /* Prefer SQLite sink; fall back to JSONL. If both, SQLite wins (JSONL is
     * kept for debug only when explicitly requested alongside --sqlite). */
    ring_buffer_sample_fn handler;
    void *handler_ctx;
    if (use_sqlite) {
        handler = handle_event_sqlite;
        handler_ctx = &sink;
    } else {
        handler = handle_event_jsonl;
        handler_ctx = out;
    }

    rb = ring_buffer__new(map_fd, handler, handler_ctx, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new: %s\n", strerror(errno));
        goto out;
    }

    fprintf(stderr, "[AgentGateway] audit consumer streaming %s -> %s%s%s\n",
            pin_path,
            use_sqlite ? sqlite_path : "(none)",
            jsonl_path ? " +jsonl:" : "",
            jsonl_path ? jsonl_path : "");
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
    if (use_sqlite)
        sqlite_sink_close(&sink);
    if (out)
        fclose(out);
    return err;
}
