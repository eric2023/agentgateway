// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
// AgentGateway Landlock helper (方案 B, P2). Applies a Landlock ABI v3 file
// boundary to the wrapped agent: read/execute everywhere, but write/remove/
// truncate/refer only beneath the allowlisted directories (default: $PWD).
//
// Usage: agent_landlock --allow <dir> [--allow <dir>...] -- <command> [args...]
//
// landlock_restrict_self is irreversible; this binary execs the command in the
// same process so the agent inherits the restriction (same PID, same cgroup).

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/landlock.h>

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif

/* "modify" access rights, minus IOCTL_DEV (ABI v4, not on 6.6). */
#define BASE_WRITE_MASK ( \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_REMOVE_DIR | \
	LANDLOCK_ACCESS_FS_REMOVE_FILE | \
	LANDLOCK_ACCESS_FS_MAKE_CHAR | \
	LANDLOCK_ACCESS_FS_MAKE_DIR | \
	LANDLOCK_ACCESS_FS_MAKE_REG | \
	LANDLOCK_ACCESS_FS_MAKE_SOCK | \
	LANDLOCK_ACCESS_FS_MAKE_FIFO | \
	LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
	LANDLOCK_ACCESS_FS_MAKE_SYM)

static __u64 fs_mask(void)
{
	__u64 mask = BASE_WRITE_MASK;
	int abi = (int)syscall(__NR_landlock_create_ruleset, NULL, 0,
			       LANDLOCK_CREATE_RULESET_VERSION);
	if (abi >= 2)
		mask |= LANDLOCK_ACCESS_FS_REFER;
	if (abi >= 3)
		mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
	return mask;
}

static int add_allow(int ruleset_fd, const char *path, __u64 mask)
{
	int dir_fd = open(path, O_PATH | O_CLOEXEC | O_DIRECTORY);
	struct landlock_path_beneath_attr pb;
	int rc;

	if (dir_fd < 0) {
		fprintf(stderr, "[agentgateway] landlock: open %s: %s\n",
			path, strerror(errno));
		return -1;
	}
	memset(&pb, 0, sizeof(pb));
	pb.allowed_access = mask;
	pb.parent_fd = dir_fd;
	rc = (int)syscall(__NR_landlock_add_rule, ruleset_fd,
			  LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
	close(dir_fd);
	if (rc < 0)
		fprintf(stderr, "[agentgateway] landlock: allow %s: %s\n",
			path, strerror(errno));
	return rc;
}

int main(int argc, char **argv)
{
	const char *allow[64];
	int nallow = 0;
	int i;
	int ruleset_fd;
	__u64 mask;
	struct landlock_ruleset_attr attr;

	/* parse --allow dir ... -- cmd... */
	i = 1;
	while (i < argc) {
		if (strcmp(argv[i], "--allow") == 0 && i + 1 < argc) {
			if (nallow < (int)(sizeof(allow) / sizeof(allow[0])))
				allow[nallow++] = argv[i + 1];
			i += 2;
			continue;
		}
		if (strcmp(argv[i], "--") == 0) {
			i++;
			break;
		}
		break;
	}
	if (i >= argc) {
		fprintf(stderr,
			"usage: %s --allow <dir> [--allow <dir>...] -- <cmd> [args...]\n",
			argv[0]);
		return 2;
	}

	mask = fs_mask();
	memset(&attr, 0, sizeof(attr));
	attr.handled_access_fs = mask;

	ruleset_fd = (int)syscall(__NR_landlock_create_ruleset, &attr,
				  sizeof(attr), 0);
	if (ruleset_fd < 0) {
		perror("[agentgateway] landlock_create_ruleset");
		return 1;
	}

	for (int a = 0; a < nallow; a++)
		add_allow(ruleset_fd, allow[a], mask);

	if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) < 0) {
		perror("[agentgateway] landlock_restrict_self");
		close(ruleset_fd);
		return 1;
	}
	close(ruleset_fd);

	execvp(argv[i], &argv[i]);
	perror("[agentgateway] execvp");
	return 1;
}
