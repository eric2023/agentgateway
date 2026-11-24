/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * AgentGateway LD_PRELOAD TLS Audit Shim
 * Hooks SSL_write/SSL_read (OpenSSL) and gnutls_record_send/gnutls_record_recv
 * (GnuTLS) to capture plaintext TLS traffic for audit purposes.
 *
 * Build: gcc -shared -fPIC -o libauditshim.so libauditshim.c -ldl
 *
 * The shim writes captured plaintext to a Unix domain socket or file,
 * which the gateway correlates with network events for tool call chain tracking.
 *
 * This is a backup mechanism — the primary interception is via HTTPS_PROXY.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>

/* ─── Configuration ─── */
#define AGENTGATEWAY_AUDIT_SOCKET "/tmp/agentgateway-audit.sock"
#define AGW_MAX_CAPTURE  4096
#define AGW_LOG_FILE     NULL  /* Set to a path to also log to file */

/* ─── Global state ─── */
static int audit_fd = -1;
static pthread_mutex_t audit_lock = PTHREAD_MUTEX_INITIALIZER;
static int initialized = 0;

/* Function pointer types */
typedef int (*ssl_write_func)(void *ssl, const void *buf, int num);
typedef int (*ssl_read_func)(void *ssl, void *buf, int num);
typedef ssize_t (*gnutls_send_func)(void *session, const void *buf, size_t count);
typedef ssize_t (*gnutls_recv_func)(void *session, void *buf, size_t count);

/* Original function pointers */
static ssl_write_func real_ssl_write = NULL;
static ssl_read_func real_ssl_read = NULL;
static gnutls_send_func real_gnutls_send = NULL;
static gnutls_recv_func real_gnutls_recv = NULL;

/* ─── Audit output ─── */
static void agw_init(void) {
    if (initialized) return;
    initialized = 1;

    const char *agent_id = getenv("AGENTGATEWAY_AGENT_ID");
    const char *session_id = getenv("AGENTGATEWAY_SESSION_ID");
    if (!agent_id) agent_id = "unknown";
    if (!session_id) session_id = "unknown";

    /* Try to connect to audit Unix socket */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, AGENTGATEWAY_AUDIT_SOCKET, sizeof(addr.sun_path) - 1);

    audit_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (audit_fd >= 0) {
        /* Non-blocking, best-effort — don't fail if socket doesn't exist */
    }

    fprintf(stderr, "[agentgateway-shim] initialized agent=%s session=%s\n",
            agent_id, session_id);
}

static void agw_log_event(const char *direction, const void *buf, int len) {
    if (len <= 0) return;

    int capture_len = len < AGW_MAX_CAPTURE ? len : AGW_MAX_CAPTURE;

    /* Build audit event */
    char header[256];
    const char *agent_id = getenv("AGENTGATEWAY_AGENT_ID");
    const char *session_id = getenv("AGENTGATEWAY_SESSION_ID");
    if (!agent_id) agent_id = "unknown";
    if (!session_id) session_id = "unknown";

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int header_len = snprintf(header, sizeof(header),
        "{\"ts\":%ld.%09ld,\"agent_id\":\"%s\",\"session_id\":\"%s\","
        "\"direction\":\"%s\",\"len\":%d,\"data\":\"",
        ts.tv_sec, ts.tv_nsec, agent_id, session_id, direction, len);

    if (header_len <= 0) return;

    pthread_mutex_lock(&audit_lock);

    /* Write to audit socket if available */
    if (audit_fd >= 0) {
        /* Send header */
        send(audit_fd, header, header_len, MSG_DONTWAIT);

        /* Send data as hex-encoded */
        char hexbuf[AGW_MAX_CAPTURE * 2 + 1];
        const unsigned char *p = (const unsigned char *)buf;
        int i;
        for (i = 0; i < capture_len && i < AGW_MAX_CAPTURE; i++) {
            snprintf(hexbuf + i * 2, 3, "%02x", p[i]);
        }
        send(audit_fd, hexbuf, capture_len * 2, MSG_DONTWAIT);
        send(audit_fd, "\"}\n", 3, MSG_DONTWAIT);
    }

    /* Also log to stderr for debugging (first 128 bytes) */
    int dbg_len = capture_len < 128 ? capture_len : 128;
    char dbg[256];
    int pos = snprintf(dbg, sizeof(dbg), "[agentgateway-shim] %s %d bytes: ", direction, len);
    memcpy(dbg + pos, buf, dbg_len);
    dbg[pos + dbg_len] = '\0';
    fprintf(stderr, "%s\n", dbg);

    pthread_mutex_unlock(&audit_lock);
}

/* ─── OpenSSL hooks ─── */
int SSL_write(void *ssl, const void *buf, int num) {
    if (!real_ssl_write) {
        real_ssl_write = (ssl_write_func)dlsym(RTLD_NEXT, "SSL_write");
    }
    int ret = real_ssl_write(ssl, buf, num);
    if (ret > 0) {
        agw_init();
        agw_log_event("ssl_write", buf, ret);
    }
    return ret;
}

int SSL_read(void *ssl, void *buf, int num) {
    if (!real_ssl_read) {
        real_ssl_read = (ssl_read_func)dlsym(RTLD_NEXT, "SSL_read");
    }
    int ret = real_ssl_read(ssl, buf, num);
    if (ret > 0) {
        agw_init();
        agw_log_event("ssl_read", buf, ret);
    }
    return ret;
}

/* ─── SSL verification bypass (for MITM proxy) ─── */
/* When LD_PRELOAD'd, we disable SSL peer verification so the gateway's
 * dynamically-signed certificates are accepted without trusting the CA.
 * We hook multiple points: SSL_CTX_set_verify, SSL_CTX_ctrl, and the
 * X509 verification callback to ensure verification always passes. */
typedef void (*ssl_ctx_set_verify_func)(void *ctx, int mode, void *verify_callback);
typedef long (*ssl_ctx_ctrl_func)(void *ctx, int cmd, long larg, void *parg);
typedef int (*x509_verify_cert_func)(void *ctx);
typedef void (*ssl_set_verify_func)(void *ssl, int mode, void *verify_callback);

/* SSL_VERIFY_NONE = 0x00 */
void SSL_CTX_set_verify(void *ctx, int mode, void *verify_callback) {
    static ssl_ctx_set_verify_func real_func = NULL;
    if (!real_func) {
        real_func = (ssl_ctx_set_verify_func)dlsym(RTLD_NEXT, "SSL_CTX_set_verify");
    }
    if (real_func) {
        real_func(ctx, 0, verify_callback);  /* Force SSL_VERIFY_NONE */
    }
}

/* Also intercept SSL_CTX_ctrl to catch SSL_CTX_set_verify via the ctrl path */
long SSL_CTX_ctrl(void *ctx, int cmd, long larg, void *parg) {
    static ssl_ctx_ctrl_func real_func = NULL;
    if (!real_func) {
        real_func = (ssl_ctx_ctrl_func)dlsym(RTLD_NEXT, "SSL_CTX_ctrl");
    }
    if (real_func) {
        /* SSL_CTRL_SET_VERIFY = 0x5F (95) */
        if (cmd == 0x5F) {
            return real_func(ctx, cmd, 0, parg);  /* Force mode=0 */
        }
        return real_func(ctx, cmd, larg, parg);
    }
    return 0;
}

/* Intercept SSL_set_verify (per-SSL, not per-CTX) */
void SSL_set_verify(void *ssl, int mode, void *verify_callback) {
    static ssl_set_verify_func real_func = NULL;
    if (!real_func) {
        real_func = (ssl_set_verify_func)dlsym(RTLD_NEXT, "SSL_set_verify");
    }
    if (real_func) {
        real_func(ssl, 0, verify_callback);  /* Force SSL_VERIFY_NONE */
    }
}

/* Override X509_verify_cert to always return success.
 * This is the last-resort hook: even if Qt sets up verification,
 * the actual cert chain check always passes. */
int X509_verify_cert(void *ctx) {
    return 1;  /* Success — cert chain verified */
}
/* ─── GnuTLS hooks ─── */
ssize_t gnutls_record_send(void *session, const void *buf, size_t count) {
    if (!real_gnutls_send) {
        real_gnutls_send = (gnutls_send_func)dlsym(RTLD_NEXT, "gnutls_record_send");
    }
    ssize_t ret = real_gnutls_send(session, buf, count);
    if (ret > 0) {
        agw_init();
        agw_log_event("gnutls_send", buf, (int)ret);
    }
    return ret;
}

ssize_t gnutls_record_recv(void *session, void *buf, size_t count) {
    if (!real_gnutls_recv) {
        real_gnutls_recv = (gnutls_recv_func)dlsym(RTLD_NEXT, "gnutls_record_recv");
    }
    ssize_t ret = real_gnutls_recv(session, buf, count);
    if (ret > 0) {
        agw_init();
        agw_log_event("gnutls_recv", buf, (int)ret);
    }
    return ret;
}

/* ─── Constructor ─── */
__attribute__((constructor))
static void agw_shim_init(void) {
    agw_init();
}
