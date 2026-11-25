// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2026 Uniontech Software Technology Co., Ltd.
// Print the cgroup id of a cgroup v2 directory — the same value
// bpf_get_current_cgroup_id() returns in the BPF program.
//
// On cgroup2 the kernfs node id (returned by name_to_handle_at) is the cgroup
// id; agw-admit's helper keys identity_map on this value.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv)
{
    int fd, mount_id = 0;
    struct {
        struct file_handle h;
        unsigned char space[64];
    } fh;
    unsigned long long id;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <cgroup-dir>\n", argv[0]);
        return 2;
    }

    fd = open(argv[1], O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    memset(&fh, 0, sizeof(fh));
    fh.h.handle_bytes = sizeof(fh.space);
    if (name_to_handle_at(fd, "", &fh.h, &mount_id, AT_EMPTY_PATH) != 0) {
        perror("name_to_handle_at");
        close(fd);
        return 1;
    }
    close(fd);

    id = *(unsigned long long *)fh.h.f_handle;
    printf("%llu\n", id);
    return 0;
}
