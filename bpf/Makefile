# AgentGateway BPF toolchain (方案 B)
#
# Build prerequisites are staged into a local prefix (no root install):
#   PREFIX ?= $(HOME)/agentgateway-toolchain
# containing clang-17, llvm-17, bpftool and libbpf-dev headers/libs
# (extracted via `apt-get download` + `dpkg -x`).

PREFIX   ?= $(HOME)/agentgateway-toolchain
CLANG    := $(PREFIX)/usr/bin/clang-17
BPFTOOL  := $(PREFIX)/usr/sbin/bpftool
CC       := gcc

INCLUDES  := -I$(PREFIX)/usr/include -I.
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 $(INCLUDES)

LIBDIR   := $(PREFIX)/usr/lib/x86_64-linux-gnu
LDFLAGS  := -L$(LIBDIR) -lbpf -lelf -lz

all: agent_lsm.bpf.o agent_lsm.skel.h agent_lsm audit_consumer cgroupid agent_admit agent_landlock \
     agent_uprobe.bpf.o agent_uprobe.skel.h agent_uprobe agent_uprobe_consumer

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

agent_lsm.bpf.o: agent_lsm.bpf.c agent_common.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

agent_lsm.skel.h: agent_lsm.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

agent_lsm: agent_lsm.c agent_lsm.skel.h
	$(CC) -g -Wall -O2 $(INCLUDES) $< -o $@ $(LDFLAGS)

audit_consumer: audit_consumer.c agent_common.h
	$(CC) -g -Wall -O2 $(INCLUDES) $< -o $@ $(LDFLAGS)

cgroupid: cgroupid.c
	$(CC) -g -Wall -O2 $< -o $@

agent_admit: agent_admit.c agent_common.h
	$(CC) -g -Wall -O2 $(INCLUDES) $< -o $@

agent_landlock: agent_landlock.c
	$(CC) -g -Wall -O2 $< -o $@

agent_uprobe.bpf.o: agent_uprobe.bpf.c agent_common.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

agent_uprobe.skel.h: agent_uprobe.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

agent_uprobe: agent_uprobe.c agent_uprobe.skel.h
	$(CC) -g -Wall -O2 $(INCLUDES) $< -o $@ $(LDFLAGS)

agent_uprobe_consumer: agent_uprobe_consumer.c agent_common.h
	$(CC) -g -Wall -O2 $(INCLUDES) $< -o $@ $(LDFLAGS)

clean:
	rm -f *.o *.skel.h agent_lsm audit_consumer cgroupid agent_admit agent_landlock \
	      agent_uprobe agent_uprobe_consumer

.PHONY: all clean
