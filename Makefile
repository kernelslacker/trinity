VERSION="2026.05"

DESTDIR ?=
PREFIX ?= /usr/local
NR_CPUS := $(shell grep -c ^processor /proc/cpuinfo)

ifeq ($(CC),)
CC := gcc
endif
CC := $(CROSS_COMPILE)$(CC)

CFLAGS ?= -g -O2 -D_FORTIFY_SOURCE=2
CFLAGS += -Wall -Wextra -I. -Iinclude/ -include config.h -Wimplicit -D_GNU_SOURCE -D__linux__

CCSTD := $(shell if $(CC) -std=gnu11 -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-std=gnu11"; else echo "-std=gnu99"; fi)
CFLAGS += $(CCSTD)

ifneq ($(SYSROOT),)
CFLAGS += --sysroot=$(SYSROOT)
endif
#CFLAGS += $(shell if $(CC) -m32 -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-m32"; fi)
CFLAGS += -Wformat=2
CFLAGS += -Winit-self
CFLAGS += -Wnested-externs
CFLAGS += -Wpacked
CFLAGS += -Wshadow
CFLAGS += -Wundef
CFLAGS += -Wwrite-strings
CFLAGS += -Wno-format-nonliteral
CFLAGS += -Wstrict-prototypes -Wmissing-prototypes
CFLAGS += -fsigned-char
# Suppress noisy missing-field-initializer warnings from generated
# BPF/UAPI-style initializers.
CFLAGS += -Wno-missing-field-initializers

# needed for show_backtrace() to work correctly.
LDFLAGS += -rdynamic

# Force eager symbol resolution at exec time (LD_BIND_NOW behaviour).
# Lazy binding walks ld.so's writable link_map. Fuzzed writes can corrupt
# that state, and later _dl_runtime_resolve/dladdr paths may fault before
# child_fault_handler can preserve a useful crash record.
LDFLAGS += -Wl,-z,now

# Runtime tripwire for libc rand().  scripts/check-static/no-libc-rand.sh
# is a build-time grep and can't see rand() that arrives via a macro
# expansion from a system / third-party header.  --wrap=rand redirects
# every link-time call to rand() into __wrap_rand in rand/rand-warn.c,
# which prints one warning per process on first hit and forwards to
# __real_rand.  srand() is not wrapped -- rand/seed.c uses it
# intentionally for the seed-reproduction path.
LDFLAGS += -Wl,--wrap=rand

# barrier_racer uses process-shared pthread barriers
LDLIBS += -lpthread

# pc_format.c uses dladdr() to resolve PIE-relative offsets
LDLIBS += -ldl

# strategy.c uses sqrt()/log() for the UCB1 bandit picker
LDLIBS += -lm

# gcc only.
ifeq ($(shell $(CC) -v 2>&1 | grep -c "clang"), 0)
CFLAGS += -Wlogical-op
CFLAGS += -Wstrict-aliasing=3
endif

# `make asan` (also `make debug` for backwards-compat) enables
# AddressSanitizer with -Og/-ggdb3 debuginfo.  AddressSanitizer catches
# shared-slab freelist overflows at the write site instead of letting
# them surface later as unrelated wild writes.  Frame pointers stay
# omitted because the 32-on-64 DO_32_SYSCALL inline asm in
# include/arch-x86-64.h clobbers %rbp; ASAN still produces good
# backtraces from the DWARF info -ggdb3 emits.  The trailing -Og
# overrides the earlier -O2; _FORTIFY_SOURCE is undefined because it
# requires optimization.
ifneq ($(filter asan debug,$(MAKECMDGOALS)),)
CFLAGS += -U_FORTIFY_SOURCE -fsanitize=address -Og -ggdb3
LDFLAGS += -fsanitize=address
endif

V	= @
Q	= $(V:1=)
QUIET_CC = $(Q:@=@echo    '  CC	'$@;)


all: trinity

asan: trinity

debug: trinity

test:
	@if [ ! -f config.h ]; then  echo "[1;31mRun ./configure first.[0m" ; exit; fi


MACHINE		:= $(shell $(CC) -dumpmachine)
SYSCALLS_ARCH	:= $(shell case "$(MACHINE)" in \
		   (x86_64*) echo syscalls/x86/*.c \
				  syscalls/x86/i386/*.c \
				  syscalls/x86/x86_64/*.c;; \
		   (i?86*) echo syscalls/x86/*.c \
				syscalls/x86/i386/*.c;; \
		   esac)

VERSION_H	:= include/version.h

HEADERS		:= $(wildcard *.h) $(wildcard syscalls/*.h) $(wildcard syscalls/clock/*.h) $(wildcard ioctls/*.h)

SRCS		:= $(wildcard *.c) \
		   $(wildcard args/*.c) \
		   $(wildcard args/pools/*.c) \
		   $(wildcard child/*.c) \
		   $(wildcard childops/*.c) \
		   $(wildcard childops/net/*.c) \
		   $(wildcard childops/net/netfilter/*.c) \
		   $(wildcard childops/net/netfilter/nftables/*.c) \
		   $(wildcard childops/net/netlink/*.c) \
		   $(wildcard childops/net/xfrm/*.c) \
		   $(wildcard childops/net/tc/*.c) \
		   $(wildcard childops/misc/*.c) \
		   $(wildcard childops/recipe/*.c) \
		   $(wildcard childops/io_uring/*.c) \
		   $(wildcard childops/mm/*.c) \
		   $(wildcard childops/fs/*.c) \
		   $(wildcard cmp_hints/*.c) \
		   $(wildcard dispatch/*.c) \
		   $(wildcard fds/*.c) \
		   $(wildcard health/*.c) \
		   $(wildcard ioctls/*.c) \
		   $(wildcard kcov/*.c) \
		   $(wildcard lib/*.c) \
		   $(wildcard main/*.c) \
		   $(wildcard main/params/*.c) \
		   $(wildcard mm/*.c) \
		   $(wildcard net/*.c) \
		   $(wildcard net/bpf/*.c) \
		   $(wildcard net/netlink/*.c) \
		   $(wildcard net/netlink/genl/*.c) \
		   $(wildcard net/netlink/nfnl/*.c) \
		   $(wildcard net/proto/*.c) \
		   $(wildcard objects/*.c) \
		   $(wildcard persist/*.c) \
		   $(wildcard rand/*.c) \
		   $(wildcard random_syscall/*.c) \
		   $(wildcard stats/*.c) \
		   $(wildcard stats/categories/*.c) \
		   $(wildcard stats/dump/*.c) \
		   $(wildcard stats/json/*.c) \
		   $(wildcard stats/subsys/*.c) \
		   $(wildcard stats/childop/*.c) \
		   $(wildcard stats/network/*.c) \
		   $(wildcard stats/kcov/*.c) \
		   $(wildcard strategy/*.c) \
		   $(wildcard struct_catalog/*.c) \
		   $(wildcard struct_catalog/registry/*.c) \
		   $(wildcard syscalls/*.c) \
		   $(wildcard syscalls/mm/memfd/*.c) \
		   $(wildcard syscalls/mm/mlock/*.c) \
		   $(wildcard syscalls/mm/numa/*.c) \
		   $(wildcard syscalls/mm/*.c) \
		   $(wildcard syscalls/fs/timestamp/*.c) \
		   $(wildcard syscalls/fs/splice/*.c) \
		   $(wildcard syscalls/fs/sync/*.c) \
		   $(wildcard syscalls/fs/mount/*.c) \
		   $(wildcard syscalls/fs/stat/*.c) \
		   $(wildcard syscalls/fs/path/*.c) \
		   $(wildcard syscalls/fs/*.c) \
		   $(wildcard syscalls/perf/*.c) \
		   $(wildcard syscalls/quota/*.c) \
		   $(wildcard syscalls/kexec/*.c) \
		   $(wildcard syscalls/uname/*.c) \
		   $(wildcard syscalls/hardware/*.c) \
		   $(wildcard syscalls/process/*.c) \
		   $(wildcard syscalls/lsm/*.c) \
		   $(wildcard syscalls/landlock/*.c) \
		   $(wildcard syscalls/pidfd/*.c) \
		   $(wildcard syscalls/module/*.c) \
		   $(wildcard syscalls/keyctl/*.c) \
		   $(wildcard syscalls/fsnotify/*.c) \
		   $(wildcard syscalls/concurrency/*.c) \
		   $(wildcard syscalls/poll/*.c) \
		   $(wildcard syscalls/aio/*.c) \
		   $(wildcard syscalls/io_uring/*.c) \
		   $(wildcard syscalls/socket/*.c) \
		   $(wildcard syscalls/mq/*.c) \
		   $(wildcard syscalls/ipc/sysv/*.c) \
		   $(wildcard syscalls/itimer/*.c) \
		   $(wildcard syscalls/timer/*.c) \
		   $(wildcard syscalls/clock/*.c) \
		   $(wildcard syscalls/signal/*.c) \
		   $(wildcard syscalls/sched/*.c) \
		   $(wildcard syscalls/cred/*.c) \
		   $(wildcard syscalls/xattr/*.c) \
		   $(wildcard tables/*.c) \
		   $(wildcard utils/*.c) \
		   $(SYSCALLS_ARCH)

OBJS		:= $(sort $(patsubst %.c,%.o,$(wildcard *.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard args/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard args/pools/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard child/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard childops/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard childops/net/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard childops/net/netfilter/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard childops/net/netfilter/nftables/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard childops/net/netlink/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard childops/net/xfrm/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard childops/net/tc/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard childops/misc/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard childops/recipe/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard childops/io_uring/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard childops/mm/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard childops/fs/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard cmp_hints/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard dispatch/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard fds/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard health/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard ioctls/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard kcov/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard lib/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard main/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard main/params/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard mm/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard net/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard net/bpf/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard net/netlink/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard net/netlink/genl/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard net/netlink/nfnl/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard net/proto/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard objects/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard persist/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard rand/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard random_syscall/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard stats/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard stats/categories/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard stats/dump/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard stats/json/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard stats/subsys/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard stats/childop/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard stats/network/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard stats/kcov/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard strategy/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard struct_catalog/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard struct_catalog/registry/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/mm/memfd/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/mm/mlock/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/mm/numa/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/mm/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/fs/timestamp/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/fs/splice/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/fs/sync/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/fs/mount/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/fs/stat/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/fs/path/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/fs/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/perf/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/quota/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/kexec/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/uname/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/hardware/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/process/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/lsm/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/landlock/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/pidfd/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/module/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/keyctl/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/fsnotify/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/concurrency/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/poll/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/aio/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/io_uring/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/socket/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/mq/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/ipc/sysv/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/itimer/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/timer/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/clock/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/signal/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/sched/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/cred/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/xattr/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard tables/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard utils/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(SYSCALLS_ARCH)))

DEPDIR= .deps

-include $(SRCS:%.c=$(DEPDIR)/%.d)

$(VERSION_H): scripts/gen-versionh.sh Makefile $(wildcard .git)
	@scripts/gen-versionh.sh

trinity: test $(OBJS) $(HEADERS)
	$(QUIET_CC)$(CC) $(CFLAGS) $(LDFLAGS) -o trinity $(OBJS) $(LDLIBS)
	@mkdir -p tmp

%.o : %.c | $(VERSION_H)
	@mkdir -p $(DEPDIR)/$(*D)
	$(QUIET_CC)$(CC) $(CFLAGS) -MMD -MF $(DEPDIR)/$*.d -o $@ -c $<

clean:
	@rm -f $(OBJS)
	@rm -f *.o args/*.o lib/*.o main/*.o main/params/*.o net/*.o objects/*.o stats/*.o stats/json/*.o tables/*.o utils/*.o
	@rm -f core.*
	@rm -f trinity
	@rm -f tags tags.json
	@rm -rf $(DEPDIR)/*
	@rm -rf trinity-coverity.tar.xz cov-int
	@rm -f $(VERSION_H)

tag:
	@git tag -a v$(VERSION) -m "$(VERSION) release."

tarball:
	@git archive --format=tar --prefix=trinity-$(VERSION)/ HEAD > trinity-$(VERSION).tar
	@xz -9 trinity-$(VERSION).tar

install: trinity
	install -d -m 755 $(DESTDIR)$(PREFIX)/bin
	install trinity $(DESTDIR)$(PREFIX)/bin

tags:	$(SRCS)
	@ctags -R --exclude=tmp --languages=C,Python,Sh

tagsjson:	$(SRCS)
	@rm -f tags.json
	@ctags -R --exclude=tmp --languages=C,Python,Sh --output-format=json --fields=+n -f tags.json

scan:
	@scan-build --use-analyzer=/usr/bin/clang make -j $(NR_CPUS)

check-static:
	@./scripts/check-static.sh

coverity:
	@rm -rf cov-int trinity-coverity.tar.xz
	@cov-build --dir cov-int make -j $(NR_CPUS)
	@tar cJvf trinity-coverity.tar.xz cov-int

# Grant the file capabilities the parent process needs:
#   - CAP_SYS_ADMIN: parent watchdog reads /proc/<pid>/stack for the
#     D-state diagnostic snapshot.
#   - CAP_SYS_RESOURCE: parent raises RLIMIT_MEMLOCK to infinity before
#     fork (rlimits.c), so children inherit enough mlock headroom for
#     mlockall() to succeed under ASAN's TB-scale shadow.
#   - CAP_DAC_READ_SEARCH: parent reads fuzz children's /proc/<pid>/ and
#     other paths regardless of DAC (children mutate their own creds).
#   - CAP_SYS_PTRACE: parent bypasses ptrace_may_access to read a
#     cred-changed / non-dumpable child's /proc/<pid>/{mem,stack,...}.
# setcap needs root (CAP_SETFCAP), so this is a standalone target:
#   make && sudo make setcap
# Re-run after every rebuild -- the security.capability xattr is stripped
# on recompile.  Needs an xattr-capable, non-nosuid fs (ext4/xfs/btrfs/
# recent tmpfs; not nfs/overlayfs).
# Depends on the child capability-drop in child-init.c: forked fuzz
# children capset() every cap (CAP_SYS_ADMIN, CAP_SYS_RESOURCE, ...) to
# empty before the fuzz loop, so the raised RLIMIT_MEMLOCK persists
# across fork while the cap that raised it does not.
setcap:
	setcap cap_sys_admin,cap_sys_resource,cap_dac_read_search,cap_sys_ptrace+ep ./trinity
