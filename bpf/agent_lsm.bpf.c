// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
// AgentGateway BPF-LSM enforcement sandbox (方案 B, P1).
//
// Attached to the `bpf` LSM (global attach). A process is "managed" when its
// cgroup id is present in identity_map, which trustexec's helper populates
// after creating the per-agent cgroup. This is the forge-proof identity that
// replaces 方案 A's environment variables (which any agent can spoof).
//
// P1 decisive advantage over 方案 A: direct non-loopback :443 from a managed
// agent is DENIED in-kernel (-EPERM) — an agent cannot bypass the gateway by
// ignoring HTTPS_PROXY.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "agent_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET 2
#define EPERM 1
#define LOOPBACK_NET 0x7f000000U /* 127.0.0.0/8 */

/* cgroup_id -> identity */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct agent_identity);
} identity_map SEC(".maps");

/* fine-grained rules (reserved) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct rule_key);
    __type(value, struct rule_value);
} rules_map SEC(".maps");

/* runtime config */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct agent_config);
} config_map SEC(".maps");

/* audit ring buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} audit_buf SEC(".maps");

/* Copy identity from identity_map into a freshly reserved event. */
static __always_inline void resolve_identity(struct audit_event *ev)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    struct agent_identity *id;

    ev->cgroup_id = cgid;
    id = bpf_map_lookup_elem(&identity_map, &cgid);
    if (!id) {
        ev->agent_id[0] = 0;
        ev->session_id[0] = 0;
        ev->app_name[0] = 0;
        return;
    }
    bpf_probe_read_kernel_str(ev->agent_id, sizeof(ev->agent_id), id->agent_id);
    bpf_probe_read_kernel_str(ev->session_id, sizeof(ev->session_id), id->session_id);
    bpf_probe_read_kernel_str(ev->app_name, sizeof(ev->app_name), id->app_name);
}

/* Return 1 if current task is managed (its cgroup id is in identity_map). */
static __always_inline int is_managed(void)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    return bpf_map_lookup_elem(&identity_map, &cgid) != NULL;
}

/*
 * socket_connect — the decisive hook. Managed agents must reach the internet
 * through the local gateway; direct non-loopback :443 is denied in-kernel.
 * NOTE: `address` here is a __user pointer (see __sys_connect_file), so it must
 * be read with bpf_probe_read_user, not bpf_probe_read_kernel.
 */
SEC("lsm/socket_connect")
int BPF_PROG(agent_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
	__u32 key = 0;
	struct agent_config *cfg;
	struct sockaddr_in addr;
	struct audit_event *ev;
	__u16 port;
	__u32 daddr;

	if (!is_managed())
		return 0;

	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (!cfg)
		return 0;

	if (!address || addrlen < (int)sizeof(struct sockaddr_in))
		return 0;

	/*
	 * NOTE: on this UOS 6.6 kernel, the socket_connect LSM hook receives the
	 * sockaddr as a *kernel* pointer (bpf_probe_read_user returns -EFAULT,
	 * bpf_probe_read_kernel succeeds). Read it accordingly.
	 */
	bpf_probe_read_kernel(&addr, sizeof(addr), address);
	if (addr.sin_family != AF_INET)
		return 0; /* ipv6 tracked separately later */

	port = bpf_ntohs(addr.sin_port);
	daddr = bpf_ntohl(addr.sin_addr.s_addr);

	if (cfg->enable_deny_443 && port == 443 &&
	    (daddr & 0xff000000U) != LOOPBACK_NET) {
		ev = bpf_ringbuf_reserve(&audit_buf, sizeof(*ev), 0);
		if (ev) {
			__builtin_memset(ev, 0, sizeof(*ev));
			ev->ts_ns = bpf_ktime_get_ns();
			ev->pid = bpf_get_current_pid_tgid() >> 32;
			ev->tgid = bpf_get_current_pid_tgid();
			ev->op_type = OP_SOCKET_CONNECT;
			ev->decision = DEC_DENY;
			ev->result = -EPERM;
			ev->dport = port;
			ev->daddr = daddr;
			resolve_identity(ev);
			bpf_ringbuf_submit(ev, 0);
		}
		return -EPERM;
	}

	return 0;
}

/* bpf_d_path is declared in <bpf/bpf_helper_defs.h> (helper id 147). */

#define O_WRONLY 1
#define O_RDWR   2
#define O_CREAT  0x40
#define O_TRUNC  0x200

static __always_inline int path_starts_with(const char *path, const char *prefix,
					    __u32 prefix_len)
{
	for (__u32 i = 0; i < prefix_len && i < AGW_PATH_MAXLEN; i++) {
		if (prefix[i] == '\0')
			break;
		if (path[i] != prefix[i])
			return 0;
	}
	return 1;
}

static __always_inline __u32 str_len(const char *s, __u32 max)
{
	__u32 i = 0;
	for (; i < max; i++)
		if (s[i] == '\0')
			break;
	return i;
}

/*
 * file_open — file boundary (方案 B, P2). With enforce_file_write, deny
 * write-opens (O_WRONLY/O_RDWR/O_CREAT/O_TRUNC) whose resolved path is outside
 * write_allow_dir. Sleepable (lsm.s) so bpf_d_path is available.
 */
SEC("lsm.s/file_open")
int BPF_PROG(agent_file_open, struct file *file)
{
	__u32 key = 0;
	struct agent_config *cfg;
	struct audit_event *ev;
	char path[AGW_PATH_MAXLEN];
	__u32 prefix_len;
	int path_len;
	int write_open;

	if (!is_managed())
		return 0;

	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (!cfg)
		return 0;

	write_open = ((file->f_flags & (O_WRONLY | O_RDWR)) != 0) ||
		     ((file->f_flags & (O_CREAT | O_TRUNC)) != 0);

	path[0] = 0;
	path_len = bpf_d_path(&file->f_path, path, sizeof(path));

	if (cfg->enforce_file_write && write_open) {
		prefix_len = str_len(cfg->write_allow_dir,
				     sizeof(cfg->write_allow_dir));
		if (prefix_len > 0 && path_len > 0 &&
		    !path_starts_with(path, cfg->write_allow_dir, prefix_len)) {
			ev = bpf_ringbuf_reserve(&audit_buf, sizeof(*ev), 0);
			if (ev) {
				__builtin_memset(ev, 0, sizeof(*ev));
				ev->ts_ns = bpf_ktime_get_ns();
				ev->pid = bpf_get_current_pid_tgid() >> 32;
				ev->tgid = bpf_get_current_pid_tgid();
				ev->op_type = OP_FILE_OPEN;
				ev->decision = DEC_DENY;
				ev->result = -1;
				resolve_identity(ev);
				if (path_len > 0)
					__builtin_memcpy(ev->path, path, sizeof(ev->path));
				bpf_ringbuf_submit(ev, 0);
			}
			return -1;
		}
	}

	if (cfg->audit_file_open) {
		ev = bpf_ringbuf_reserve(&audit_buf, sizeof(*ev), 0);
		if (ev) {
			__builtin_memset(ev, 0, sizeof(*ev));
			ev->ts_ns = bpf_ktime_get_ns();
			ev->pid = bpf_get_current_pid_tgid() >> 32;
			ev->tgid = bpf_get_current_pid_tgid();
			ev->op_type = OP_FILE_OPEN;
			ev->decision = DEC_AUDIT;
			ev->result = 0;
			resolve_identity(ev);
			if (path_len > 0)
				__builtin_memcpy(ev->path, path, sizeof(ev->path));
			bpf_ringbuf_submit(ev, 0);
		}
	}

	return 0;
}

/*
 * bpf — self-protection (方案 B, P5). A managed agent has no business issuing
 * bpf() syscalls; deny them in-kernel (defense-in-depth on top of
 * kernel.unprivileged_bpf_disabled=2, which already blocks non-root BPF).
 * This also makes it impossible for a managed agent to unload/inspect the
 * AgentGateway programs or maps.
 */
SEC("lsm/bpf")
int BPF_PROG(agent_bpf_check, int cmd, union bpf_attr *attr, unsigned int size)
{
	struct audit_event *ev;

	if (!is_managed())
		return 0;

	ev = bpf_ringbuf_reserve(&audit_buf, sizeof(*ev), 0);
	if (ev) {
		__builtin_memset(ev, 0, sizeof(*ev));
		ev->ts_ns = bpf_ktime_get_ns();
		ev->pid = bpf_get_current_pid_tgid() >> 32;
		ev->tgid = bpf_get_current_pid_tgid();
		ev->op_type = OP_BPF;
		ev->decision = DEC_DENY;
		ev->result = -EPERM;
		ev->dport = (__u16)cmd;
		resolve_identity(ev);
		bpf_ringbuf_submit(ev, 0);
	}
	return -EPERM;
}

/*
 * bprm_check — audit program execution for managed agents. bprm->filename is a
 * kernel pointer to the executable path; read directly in sleepable context.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(agent_bprm_check, struct linux_binprm *bprm)
{
    __u32 key = 0;
    struct agent_config *cfg;
    struct audit_event *ev;

    if (!is_managed())
        return 0;

    cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg || !cfg->audit_bprm_check)
        return 0;

    ev = bpf_ringbuf_reserve(&audit_buf, sizeof(*ev), 0);
    if (ev) {
        __builtin_memset(ev, 0, sizeof(*ev));
        ev->ts_ns = bpf_ktime_get_ns();
        ev->pid = bpf_get_current_pid_tgid() >> 32;
        ev->tgid = bpf_get_current_pid_tgid();
        ev->op_type = OP_BPRM_CHECK;
        ev->decision = DEC_AUDIT;
        ev->result = 0;
        resolve_identity(ev);
        bpf_probe_read_kernel_str(ev->path, sizeof(ev->path), bprm->filename);
        bpf_ringbuf_submit(ev, 0);
    }
    return 0;
}
