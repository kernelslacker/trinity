VERSION="2026.05"

DESTDIR ?=
PREFIX ?= /usr/local
NR_CPUS := $(shell grep -c ^processor /proc/cpuinfo)

ifeq ($(CC),)
CC := gcc
endif
CC := $(CROSS_COMPILE)$(CC)

# Where objects land and which config.h every compile includes.
# `make uapi-check` points both at a build directory of its own.  The
# config.h directory leads the include path, so a file that names
# "config.h" itself gets the same one.
OBJDIR :=
CONFIG_H := config.h

CFLAGS ?= -g -O2 -D_FORTIFY_SOURCE=2
CFLAGS += -Wall -Wextra -I$(dir $(CONFIG_H)) -I. -Iinclude/ -include $(CONFIG_H) -Wimplicit -D_GNU_SOURCE -D__linux__

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
# __real_rand.
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

# Every compile includes config.h, which only ./configure creates.  The
# compile rule lists this order-only: a phony prerequisite that counted
# would make every object out of date on every make.
.PHONY: check-config
check-config:
	@if [ ! -f $(CONFIG_H) ]; then  echo "[1;31mRun ./configure first.[0m" >&2; exit 1; fi

# PURE-module test binary integration paths (arch-program #10).
#
# `make test-bin`    -- build the tests/ binary against the fake
#                       shm+RNG providers and run it.
# `make test-asan`   -- rebuild under -fsanitize=address + run with
#                       the default fixed seed (0xa17e57).  This is
#                       the canonical single-shot integration
#                       invocation: any BUG() from a selftest lands
#                       as an ASAN report on the same seed every
#                       time, so a failure is instantly reproducible.
# `make test-ndebug` -- rebuild under -DNDEBUG + run.  Exercises the
#                       release-build code paths (assert() compiled
#                       out); all twelve fixtures must pass green.
#
# All three targets shell out to tests/Makefile, which keys its object
# directory and output binary by flavor (build/+test-bin for normal,
# build-asan/+test-bin-asan for ASAN, build-ndebug/+test-bin-ndebug for
# NDEBUG) so alternating targets never link incompatible .o files.
# Its default goal also runs the binary once it is built, so the recipes
# below do not.
# New PURE modules migrate onto the test-bin cargo by adding one line
# to tests/Makefile REAL_SRCS, not by wiring anything here.
.PHONY: test-bin test-asan test-ndebug

test-bin: check-config
	@$(MAKE) --no-print-directory -C tests

test-asan: check-config
	@$(MAKE) --no-print-directory -C tests ASAN=1

test-ndebug: check-config
	@$(MAKE) --no-print-directory -C tests NDEBUG=1


MACHINE		:= $(shell $(CC) -dumpmachine)
SYSCALLS_ARCH	:= $(shell case "$(MACHINE)" in \
		   (x86_64*) echo syscalls/x86/*.c \
				  syscalls/x86/i386/*.c \
				  syscalls/x86/x86_64/*.c;; \
		   (i?86*) echo syscalls/x86/*.c \
				syscalls/x86/i386/*.c;; \
		   esac)

VERSION_H	:= include/version.h

# OBJS is derived from SRCS, so this is also the link order, and with it
# the order constructors register fd providers and ioctl groups in.
# $(wildcard) follows the locale's collation, hence the $(sort)s.
SRCS		:= $(sort $(wildcard args/*.c)) \
		   $(sort $(wildcard args/pools/*.c)) \
		   $(sort $(wildcard child/*.c)) \
		   $(sort $(wildcard childops/net/*.c)) \
		   $(sort $(wildcard childops/misc/*.c)) \
		   $(sort $(wildcard childops/mm/*.c)) \
		   $(sort $(wildcard childops/fs/*.c)) \
		   $(sort $(wildcard cmp_hints/*.c)) \
		   $(sort $(wildcard dispatch/*.c)) \
		   $(sort $(wildcard fds/*.c)) \
		   $(sort $(wildcard health/*.c)) \
		   $(sort $(wildcard ioctls/*.c)) \
		   $(sort $(wildcard kcov/*.c)) \
		   $(sort $(wildcard lib/*.c)) \
		   $(sort $(wildcard main/*.c)) \
		   $(sort $(wildcard main/params/*.c)) \
		   $(sort $(wildcard mm/*.c)) \
		   $(sort $(wildcard net/*.c)) \
		   $(sort $(wildcard net/bpf/*.c)) \
		   $(sort $(wildcard net/netlink/*.c)) \
		   $(sort $(wildcard net/netlink/genl/*.c)) \
		   $(sort $(wildcard net/netlink/nfnl/*.c)) \
		   $(sort $(wildcard net/proto/*.c)) \
		   $(sort $(wildcard objects/*.c)) \
		   $(sort $(wildcard persist/*.c)) \
		   $(sort $(wildcard rand/*.c)) \
		   $(sort $(wildcard random_syscall/*.c)) \
		   $(sort $(wildcard stats/*.c)) \
		   $(sort $(wildcard stats/categories/*.c)) \
		   $(sort $(wildcard stats/dump/*.c)) \
		   $(sort $(wildcard stats/json/*.c)) \
		   $(sort $(wildcard stats/subsys/*.c)) \
		   $(sort $(wildcard stats/childop/*.c)) \
		   $(sort $(wildcard stats/network/*.c)) \
		   $(sort $(wildcard stats/kcov/*.c)) \
		   $(sort $(wildcard stats/kcov/cmp/*.c)) \
		   $(sort $(wildcard stats/periodic/*.c)) \
		   $(sort $(wildcard strategy/*.c)) \
		   $(sort $(wildcard struct_catalog/*.c)) \
		   $(sort $(wildcard struct_catalog/registry/*.c)) \
		   $(sort $(wildcard syscalls/*.c)) \
		   $(sort $(wildcard syscalls/mm/memfd/*.c)) \
		   $(sort $(wildcard syscalls/mm/mlock/*.c)) \
		   $(sort $(wildcard syscalls/mm/numa/*.c)) \
		   $(sort $(wildcard syscalls/mm/*.c)) \
		   $(sort $(wildcard syscalls/fs/timestamp/*.c)) \
		   $(sort $(wildcard syscalls/fs/splice/*.c)) \
		   $(sort $(wildcard syscalls/fs/sync/*.c)) \
		   $(sort $(wildcard syscalls/fs/mount/*.c)) \
		   $(sort $(wildcard syscalls/fs/stat/*.c)) \
		   $(sort $(wildcard syscalls/fs/path/*.c)) \
		   $(sort $(wildcard syscalls/fs/*.c)) \
		   $(sort $(wildcard syscalls/perf/*.c)) \
		   $(sort $(wildcard syscalls/quota/*.c)) \
		   $(sort $(wildcard syscalls/kexec/*.c)) \
		   $(sort $(wildcard syscalls/uname/*.c)) \
		   $(sort $(wildcard syscalls/hardware/*.c)) \
		   $(sort $(wildcard syscalls/process/*.c)) \
		   $(sort $(wildcard syscalls/lsm/*.c)) \
		   $(sort $(wildcard syscalls/landlock/*.c)) \
		   $(sort $(wildcard syscalls/pidfd/*.c)) \
		   $(sort $(wildcard syscalls/module/*.c)) \
		   $(sort $(wildcard syscalls/keyctl/*.c)) \
		   $(sort $(wildcard syscalls/fsnotify/*.c)) \
		   $(sort $(wildcard syscalls/concurrency/*.c)) \
		   $(sort $(wildcard syscalls/poll/*.c)) \
		   $(sort $(wildcard syscalls/aio/*.c)) \
		   $(sort $(wildcard syscalls/io_uring/*.c)) \
		   $(sort $(wildcard syscalls/socket/*.c)) \
		   $(sort $(wildcard syscalls/mq/*.c)) \
		   $(sort $(wildcard syscalls/ipc/sysv/*.c)) \
		   $(sort $(wildcard syscalls/itimer/*.c)) \
		   $(sort $(wildcard syscalls/timer/*.c)) \
		   $(sort $(wildcard syscalls/clock/*.c)) \
		   $(sort $(wildcard syscalls/signal/*.c)) \
		   $(sort $(wildcard syscalls/sched/*.c)) \
		   $(sort $(wildcard syscalls/cred/*.c)) \
		   $(sort $(wildcard syscalls/xattr/*.c)) \
		   $(sort $(wildcard tables/*.c)) \
		   $(sort $(wildcard utils/*.c)) \
		   $(sort $(SYSCALLS_ARCH))

OBJS		:= $(SRCS:%.c=$(OBJDIR)%.o)

DEPDIR= .deps

-include $(SRCS:%.c=$(OBJDIR)$(DEPDIR)/%.d)

$(VERSION_H): scripts/gen-versionh.sh Makefile $(wildcard .git)
	@scripts/gen-versionh.sh

trinity: $(OBJS)
	$(QUIET_CC)$(CC) $(CFLAGS) $(LDFLAGS) -o trinity $(OBJS) $(LDLIBS)
	@mkdir -p tmp

# -MP gives each header an empty rule, so a deleted or renamed one does
# not break the next build.
$(OBJDIR)%.o : %.c | check-config $(VERSION_H)
	@mkdir -p $(OBJDIR)$(DEPDIR)/$(*D) $(@D)
	$(QUIET_CC)$(CC) $(CFLAGS) -MMD -MP -MF $(OBJDIR)$(DEPDIR)/$*.d -o $@ -c $<

clean:
	@rm -f $(OBJS)
	@rm -f *.o args/*.o lib/*.o main/*.o main/params/*.o net/*.o objects/*.o stats/*.o stats/json/*.o stats/periodic/*.o tables/*.o utils/*.o
	@rm -f core.*
	@rm -f trinity
	@$(MAKE) --no-print-directory -C tests clean
	@rm -f tags tags.json
	@rm -rf $(DEPDIR)/*
	@rm -rf build-uapi
	@rm -rf trinity-coverity.tar.xz cov-int
	@rm -f $(VERSION_H)
	@find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	@find . -name '*.pyc' -delete

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
	@scan-build --use-analyzer=/usr/bin/clang make -B -j $(NR_CPUS)

check-static:
	@./scripts/check-static.sh

# Opt-in, and deliberately not part of check-static: this one execs
# ./trinity (--dry-run, under timeout, via scripts/run-trinity.sh) to
# cross-check the live JSON/JSONL output against the schema baselines.
# The build runs first, so the baselines are never checked against an
# old binary.  Run it only on a host where starting the fuzzer is
# acceptable.
check-runtime: trinity
	@./scripts/check-runtime-json-output.sh

# `make uapi-check KERNEL_SRC=<kernel git tree>` compiles the tree and
# the test-binary objects against the uapi headers of an older kernel, to
# catch a symbol the build host's newer headers supply that no fallback
# covers; Documentation/HACKING.txt says why UAPI_TAG defaults to v6.12.
# scripts/uapi-sysroot.sh installs the tag's headers from KERNEL_SRC,
# never writing to it, into a sysroot cached under
# $XDG_CACHE_HOME/trinity-uapi ($HOME/.cache/trinity-uapi when that is
# unset).  configure and the objects run in build-uapi/<tag>, apart from
# the main build.  Nothing is linked and nothing is run.  A CFLAGS taken
# from the environment comes back from make fully expanded, naming the
# tree's own config.h, so configure and the sub-makes start without it.
UAPI_TAG	?= v6.12
UAPI_SYSROOT	:= $(or $(XDG_CACHE_HOME),$(HOME)/.cache)/trinity-uapi/$(UAPI_TAG)
UAPI_BUILD	:= $(CURDIR)/build-uapi/$(UAPI_TAG)
UAPI_JOBS	= $(if $(findstring -j,$(MAKEFLAGS)),,-j$(NR_CPUS))

.PHONY: uapi-check uapi-objs
uapi-check:
	@if [ -z "$(KERNEL_SRC)" ]; then echo "usage: make uapi-check KERNEL_SRC=<kernel git tree> [UAPI_TAG=$(UAPI_TAG)]" >&2; exit 1; fi
	@CC="$(CC)" scripts/uapi-sysroot.sh "$(KERNEL_SRC)" "$(UAPI_TAG)" "$(UAPI_SYSROOT)"
	@mkdir -p $(UAPI_BUILD)
	@cd $(UAPI_BUILD) && env -u CFLAGS CC="$(CC)" SYSROOT="$(UAPI_SYSROOT)" \
		$(CURDIR)/configure > configure.log
	@env -u CFLAGS $(MAKE) --no-print-directory $(UAPI_JOBS) OBJDIR=$(UAPI_BUILD)/ \
		CONFIG_H=$(UAPI_BUILD)/config.h SYSROOT="$(UAPI_SYSROOT)" uapi-objs
	@env -u CFLAGS $(MAKE) -s --no-print-directory $(UAPI_JOBS) -C tests BUILDDIR=$(UAPI_BUILD)/tests \
		CONFIG_H=$(UAPI_BUILD)/config.h SYSROOT="$(UAPI_SYSROOT)" objs
	@echo "uapi-check: trinity and test objects compile against $(UAPI_TAG) uapi headers"

uapi-objs: $(OBJS)

coverity:
	@rm -rf cov-int trinity-coverity.tar.xz
	@cov-build --dir cov-int make -B -j $(NR_CPUS)
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
