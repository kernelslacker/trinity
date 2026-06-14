/*
 * KCOV coverage collection for coverage-guided fuzzing.
 *
 * Each child tries to open /sys/kernel/debug/kcov at startup. If the
 * kernel supports KCOV, per-thread trace buffers are mmapped and PC
 * tracing is enabled around each syscall. Collected PCs are hashed
 * into a global shared bucket-seen table to track edge coverage with
 * AFL-style hit-count bucketing: a syscall that hits the same edge five
 * times is distinguishable from one that hits it two hundred times, so
 * mutations that nudge loop-trip counts past bucket boundaries register
 * as new coverage.
 *
 * When KCOV_REMOTE_ENABLE is available, a fraction of syscalls use
 * remote mode to also collect coverage from softirqs, threaded IRQ
 * handlers, and kthreads triggered by the syscall — deferred work
 * that per-thread KCOV_ENABLE would miss.
 *
 * If KCOV is not available, everything is silently skipped with no
 * runtime overhead beyond the initial open() attempt per child.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "cmp_hints.h"
#include "fd.h"
#include "kcov.h"
#include "params.h"
#include "persist-util.h"
#include "pids.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/* KCOV ioctl commands (from linux/kcov.h). */
#define KCOV_INIT_TRACE    _IOR('c', 1, unsigned long)
#define KCOV_ENABLE        _IO('c', 100)
#define KCOV_DISABLE       _IO('c', 101)
#define KCOV_REMOTE_ENABLE _IOW('c', 102, struct kcov_remote_arg)

/*
 * Park the per-child kcov fds well above the low-numbered range the
 * kernel typically hands out.  kcov_init_child runs in the child after
 * std{in,out,err} have been dup2'd to /dev/null but before the main
 * syscall loop starts, so the kernel returns lowest-available (3, 4,
 * ...) which is squarely inside the working set of trinity's argument
 * generators -- every live-fd-ring slot, every typed-fd reroll.
 * F_DUPFD_CLOEXEC-relocating the kcov slots up out of that range drops
 * the incidental hit rate sharply.  The protected-fd registry remains
 * the actual safety net; the relocation is defence-in-depth.
 *
 * 60000 sits inside the RLIMIT_NOFILE=65536 lifted by
 * scripts/run-trinity.sh, leaving ~5500 fds of headroom above for
 * the rest of trinity's working set (well above current usage).
 * The wider gap matters: at the old 900, a fuzzer-picker that
 * happens to allocate fds densely (epoll/eventfd churn,
 * slab-cache-thrash op, etc.) could land siblings in the same
 * numeric range as KCOV's relocated slots, reintroducing the
 * collision the relocation was meant to prevent.  Parking KCOV
 * at 60000 keeps it clear of any plausible picker fd range and
 * is defence-in-depth against a stale-close race producing the
 * EBADF cascade.  If the dup fails for any reason the original
 * low fd is kept and the registry catches subsequent attempts
 * on it.
 */
#define KCOV_FD_HIGH_BASE 60000U

/*
 * Userspace copy of struct kcov_remote_arg from linux/kcov.h.
 * We define it here to avoid requiring kernel headers at build time.
 */
struct kcov_remote_arg {
	uint32_t	trace_mode;
	uint32_t	area_size;
	uint32_t	num_handles;
	uint32_t	__pad;
	uint64_t	common_handle;
	uint64_t	handles[];
};

struct kcov_shared *kcov_shm = NULL;

/* The per-childop arrays in struct kcov_shared are sized off
 * KCOV_CHILDOP_NR_MAX because include/kcov.h cannot pull in child.h
 * for the real NR_CHILD_OP_TYPES (child.h includes kcov.h for struct
 * kcov_child).  Bump KCOV_CHILDOP_NR_MAX in include/kcov.h if a
 * childop slot beyond the bound is ever added. */
_Static_assert(NR_CHILD_OP_TYPES <= KCOV_CHILDOP_NR_MAX,
	"NR_CHILD_OP_TYPES exceeds KCOV_CHILDOP_NR_MAX; "
	"bump KCOV_CHILDOP_NR_MAX in include/kcov.h");

enum childop_kcov_attribution_mode childop_kcov_attr_mode =
	CHILDOP_KCOV_ATTR_OFF;

/* Default is SHADOW: collect into the transition map and surface it
 * through the stats dump, but do not feed deltas into any steering
 * consumer.  See the kcov_transition_coverage_mode enum in include/
 * kcov.h for the contract. */
enum kcov_transition_coverage_mode kcov_transition_coverage_mode =
	KCOV_TRANSITION_COVERAGE_SHADOW;

/*
 * Record a KCOV PC or remote enable/disable failure into the parent-
 * visible pc_diag slots.  Called from child context (post-dup2-to-
 * /dev/null), where output() to stdout is silently dropped — the shm
 * fields are the only diagnostic channel that survives back to the
 * parent.
 *
 * First failure wins for the errno slot: CAS-from-zero so subsequent
 * failures at the same site don't overwrite the original errno.  The
 * count slot atomically tallies every failure so the parent can see
 * how many children hit each site even when they all hit the same one.
 */
static void kcov_diag_record(int *errno_slot, unsigned int *count_slot,
			     int err)
{
	int expected = 0;
	__atomic_compare_exchange_n(errno_slot, &expected, err, false,
		__ATOMIC_RELAXED, __ATOMIC_RELAXED);
	__atomic_fetch_add(count_slot, 1, __ATOMIC_RELAXED);
}

/* strerrorname_np() returns the errno macro name ("EBADF", "ENOMEM",
 * …) for a known value or NULL otherwise.  Wrap it so the format
 * string can always splice in a non-NULL pointer even for the
 * unexpected-value path. */
static const char *errno_name_or(const char *fallback, int err)
{
	const char *n = strerrorname_np(err);
	return n ? n : fallback;
}

/* Shared formatter for the per-site KCOV CMP DIAG segments.  Both the
 * dump_stats periodic dump (stats.c) and the print_kcov_cmp_diag main
 * loop summary (main.c) walked the same six fields with copy-pasted
 * snprintf chains; centralising the format here keeps the two
 * callsites in lockstep and is the natural home alongside the
 * cmp_diag struct definition.  Fields are read once via __atomic
 * loads so the snapshot is consistent across the format pass.  Each
 * non-zero counter contributes a single space-prefixed
 * " name=ERRNO_MACRO(errno_val)/count" token; absent counters
 * contribute nothing.  The errno integer is preserved inside the
 * parentheses so existing log-grep tooling that keys on the digit
 * keeps matching, while the macro name surfaces the class of failure
 * at a glance (e.g. EBADF vs the expected ENOTTY documented in
 * kcov_enable_cmp()). */
int kcov_cmp_diag_format(char *buf, size_t bufsz, enum kcov_cmp_diag_part part)
{
	struct kcov_cmp_diag *d;
	unsigned int open_c, init_trace_c, mmap_c;
	unsigned int enable_c, disable_c, rt_enable_c;
	bool want_init, want_rt;
	int n = 0;

	if (buf == NULL || bufsz == 0)
		return 0;
	buf[0] = '\0';
	if (kcov_shm == NULL)
		return 0;

	want_init = (part == KCOV_CMP_DIAG_INIT    || part == KCOV_CMP_DIAG_ALL);
	want_rt   = (part == KCOV_CMP_DIAG_RUNTIME || part == KCOV_CMP_DIAG_ALL);

	d = &kcov_shm->cmp_diag;
	open_c       = __atomic_load_n(&d->init_open_count,       __ATOMIC_RELAXED);
	init_trace_c = __atomic_load_n(&d->init_init_trace_count, __ATOMIC_RELAXED);
	mmap_c       = __atomic_load_n(&d->init_mmap_count,       __ATOMIC_RELAXED);
	enable_c     = __atomic_load_n(&d->init_enable_count,     __ATOMIC_RELAXED);
	disable_c    = __atomic_load_n(&d->init_disable_count,    __ATOMIC_RELAXED);
	rt_enable_c  = __atomic_load_n(&d->runtime_enable_count,  __ATOMIC_RELAXED);

	/* Each token is gated on (size_t)n < bufsz so once snprintf has
	 * filled (or its would-have-written return drove n past) the
	 * caller's buffer, the chain stops appending.  Without the gate,
	 * bufsz - n is computed in size_t arithmetic and wraps to a huge
	 * positive length once n >= bufsz; snprintf cheerfully honours it
	 * and writes past the end.  stats.c passes 256-byte buffers, well
	 * within reach of a handful of ~30-40-char errno tokens.  The
	 * (size_t) cast also catches a stray snprintf -1 driving n
	 * negative -- it folds to SIZE_MAX and the comparison still
	 * bails. */
	if (want_init) {
		if (open_c && (size_t)n < bufsz) {
			int e = __atomic_load_n(&d->init_open_errno, __ATOMIC_RELAXED);
			n += snprintf(buf + n, bufsz - n, " init_open=%s(%d)/%u",
				errno_name_or("?", e), e, open_c);
		}
		if (init_trace_c && (size_t)n < bufsz) {
			int e = __atomic_load_n(&d->init_init_trace_errno, __ATOMIC_RELAXED);
			n += snprintf(buf + n, bufsz - n, " init_init_trace=%s(%d)/%u",
				errno_name_or("?", e), e, init_trace_c);
		}
		if (mmap_c && (size_t)n < bufsz) {
			int e = __atomic_load_n(&d->init_mmap_errno, __ATOMIC_RELAXED);
			n += snprintf(buf + n, bufsz - n, " init_mmap=%s(%d)/%u",
				errno_name_or("?", e), e, mmap_c);
		}
	}
	if (want_rt) {
		if (enable_c && (size_t)n < bufsz) {
			int e = __atomic_load_n(&d->init_enable_errno, __ATOMIC_RELAXED);
			n += snprintf(buf + n, bufsz - n, " init_enable=%s(%d)/%u",
				errno_name_or("?", e), e, enable_c);
		}
		if (disable_c && (size_t)n < bufsz) {
			int e = __atomic_load_n(&d->init_disable_errno, __ATOMIC_RELAXED);
			n += snprintf(buf + n, bufsz - n, " init_disable=%s(%d)/%u",
				errno_name_or("?", e), e, disable_c);
		}
		if (rt_enable_c && (size_t)n < bufsz) {
			int e = __atomic_load_n(&d->runtime_enable_errno, __ATOMIC_RELAXED);
			n += snprintf(buf + n, bufsz - n, " runtime_enable=%s(%d)/%u",
				errno_name_or("?", e), e, rt_enable_c);
		}
	}

	return n;
}

/* PC/remote sibling of kcov_cmp_diag_format.  Walks the slots in
 * struct kcov_pc_diag the same way: snapshot all counters via
 * __atomic loads, then emit one space-prefixed token per non-zero
 * site so callers can splice the buffer straight into a log line.
 * The three errno+count sites use the same "name=ERRNO(errno)/count"
 * shape; the success and EINTR-retry tallies are plain
 * "name=count" tokens. */
int kcov_pc_diag_format(char *buf, size_t bufsz)
{
	struct kcov_pc_diag *d;
	unsigned int pc_en_c, pc_dis_c, rem_en_c;
	unsigned int fb_to_pc, pc_eintr, rem_eintr, fb_pc_eintr;
	unsigned long first_op_nr;
	int n = 0;

	if (buf == NULL || bufsz == 0)
		return 0;
	buf[0] = '\0';
	if (kcov_shm == NULL)
		return 0;

	d = &kcov_shm->pc_diag;
	pc_en_c     = __atomic_load_n(&d->pc_enable_count,                    __ATOMIC_RELAXED);
	pc_dis_c    = __atomic_load_n(&d->pc_disable_count,                   __ATOMIC_RELAXED);
	rem_en_c    = __atomic_load_n(&d->remote_enable_count,                __ATOMIC_RELAXED);
	fb_to_pc    = __atomic_load_n(&d->remote_fallback_to_pc,              __ATOMIC_RELAXED);
	pc_eintr    = __atomic_load_n(&d->pc_enable_eintr_retries,            __ATOMIC_RELAXED);
	rem_eintr   = __atomic_load_n(&d->remote_enable_eintr_retries,        __ATOMIC_RELAXED);
	fb_pc_eintr = __atomic_load_n(&d->remote_fallback_pc_enable_eintr_retries, __ATOMIC_RELAXED);
	first_op_nr = __atomic_load_n(&d->first_ebadf_op_nr,                  __ATOMIC_RELAXED);

	/* See kcov_cmp_diag_format() for why each emission is gated on
	 * (size_t)n < bufsz: once n catches up to bufsz, the next
	 * bufsz - n underflows in size_t arithmetic and snprintf walks
	 * off the end of the caller's buffer.  Same 256-byte stats.c
	 * buffer is in play here too. */
	if (pc_en_c && (size_t)n < bufsz) {
		int e = __atomic_load_n(&d->pc_enable_errno, __ATOMIC_RELAXED);
		n += snprintf(buf + n, bufsz - n, " pc_enable=%s(%d)/%u",
			errno_name_or("?", e), e, pc_en_c);
	}
	if (pc_dis_c && (size_t)n < bufsz) {
		int e = __atomic_load_n(&d->pc_disable_errno, __ATOMIC_RELAXED);
		n += snprintf(buf + n, bufsz - n, " pc_disable=%s(%d)/%u",
			errno_name_or("?", e), e, pc_dis_c);
	}
	if (rem_en_c && (size_t)n < bufsz) {
		int e = __atomic_load_n(&d->remote_enable_errno, __ATOMIC_RELAXED);
		n += snprintf(buf + n, bufsz - n, " remote_enable=%s(%d)/%u",
			errno_name_or("?", e), e, rem_en_c);
	}
	if (fb_to_pc && (size_t)n < bufsz)
		n += snprintf(buf + n, bufsz - n, " remote_fallback_to_pc=%u", fb_to_pc);
	if (pc_eintr && (size_t)n < bufsz)
		n += snprintf(buf + n, bufsz - n, " pc_enable_eintr=%u", pc_eintr);
	if (rem_eintr && (size_t)n < bufsz)
		n += snprintf(buf + n, bufsz - n, " remote_enable_eintr=%u", rem_eintr);
	if (fb_pc_eintr && (size_t)n < bufsz)
		n += snprintf(buf + n, bufsz - n, " remote_fallback_pc_enable_eintr=%u", fb_pc_eintr);
	if (first_op_nr && (size_t)n < bufsz) {
		unsigned long pid = __atomic_load_n(&d->first_ebadf_pid,
			__ATOMIC_RELAXED);
		unsigned int syscall_nr = __atomic_load_n(
			&d->first_ebadf_syscall_nr, __ATOMIC_RELAXED);
		int fd_value = __atomic_load_n(&d->first_ebadf_fd_value,
			__ATOMIC_RELAXED);

		/* op_nr was stored as child->op_nr + 1 so the empty-slot
		 * sentinel (0) is distinguishable from a legitimate first-
		 * syscall capture; undo that here for the operator. */
		n += snprintf(buf + n, bufsz - n,
			" first_ebadf=op%lu:pid%lu:nr%u:fd%d",
			first_op_nr - 1, pid, syscall_nr, fd_value);
	}

	return n;
}

/*
 * Runtime base of the kernel text segment, read once from /proc/kallsyms
 * (address of "_text"; "_stext" as a fallback).  Subtracted from every PC
 * before it hits the bucket_seen[] hash so the bucket index for a given
 * instruction is invariant across KASLR reboots of the same kernel build
 * -- the warm-start cache stays useful across reboots that the kallsyms
 * fingerprint already considers identical.
 *
 * Zero means "base unavailable" (kallsyms unreadable, _text/_stext
 * absent, or kptr_restrict zeroed every address).  PCs are then hashed
 * raw; warm-start save / load is mutually compatible only across runs
 * where the base is also zero on the other side -- the load path
 * rejects a canonical-vs-raw mismatch.
 *
 * Populated by kcov_init_global before any child forks so the value
 * propagates by COW; callers in hot paths read kcov_kaslr_base
 * directly without re-entering this lookup.
 */
static uint64_t kcov_kaslr_base;
static bool     kcov_kaslr_base_valid;

static uint64_t kcov_get_kaslr_base(void)
{
	FILE *f;
	char line[4096];
	uint64_t text_addr = 0;
	uint64_t stext_addr = 0;

	if (kcov_kaslr_base_valid)
		return kcov_kaslr_base;

	f = fopen("/proc/kallsyms", "r");
	if (f == NULL) {
		output(0, "kcov-bitmap: open(/proc/kallsyms) failed: %s -- KASLR base unavailable, PCs hashed raw this run\n",
		       strerror(errno));
		kcov_kaslr_base_valid = true;
		return 0;
	}
	while (fgets(line, sizeof(line), f) != NULL) {
		unsigned long long addr;
		char type;
		char name[256];

		if (sscanf(line, "%llx %c %255s", &addr, &type, name) != 3)
			continue;
		if (strcmp(name, "_text") == 0) {
			text_addr = addr;
			/* Prefer _text; no point scanning further. */
			break;
		}
		if (strcmp(name, "_stext") == 0)
			stext_addr = addr;
	}
	if (ferror(f))
		output(0, "kcov-bitmap: read error on /proc/kallsyms -- KASLR base may be incomplete\n");
	(void)fclose(f);

	if (text_addr == 0)
		text_addr = stext_addr;
	if (text_addr == 0)
		output(0, "kcov-bitmap: _text/_stext not in kallsyms (kptr_restrict zeroed addresses?) -- KASLR base unavailable, PCs hashed raw this run\n");

	kcov_kaslr_base = text_addr;
	kcov_kaslr_base_valid = true;
	return kcov_kaslr_base;
}

void kcov_init_global(void)
{
	int fd;

	/* Probe whether KCOV is available before allocating shared memory. */
	fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (fd < 0)
		return;
	close(fd);

	/*
	 * Wild-write risk: a child syscall whose user-buffer arg aliases
	 * into kcov_shm could let the kernel corrupt the bucket_seen table
	 * (false-positive coverage inflation, including spurious bucket
	 * bits) or the per-syscall counters (a bogus last_edge_at value
	 * would stick a syscall in or out of the cold-skip pool).
	 * Diagnostics only; doesn't crash the parent.
	 */
	kcov_shm = alloc_shared_pool(sizeof(struct kcov_shared));
	memset(kcov_shm, 0, sizeof(struct kcov_shared));
	output(0, "KCOV: coverage collection enabled (%lu MB bucket-seen table, %u edges, %u buckets; counters: distinct_edges=%lu, edges_found=%lu bucket-transitions)\n",
		(unsigned long)KCOV_NUM_EDGES / (1024 * 1024),
		KCOV_NUM_EDGES, KCOV_NUM_BUCKETS,
		kcov_shm->distinct_edges, kcov_shm->edges_found);
	output(0, "KCOV: shadow transition coverage mode=%s (%lu MB transition map, %lu slots)\n",
		kcov_transition_coverage_mode == KCOV_TRANSITION_COVERAGE_SHADOW
			? "shadow" : "off",
		(unsigned long)KCOV_NUM_TRANSITIONS / (1024 * 1024),
		(unsigned long)KCOV_NUM_TRANSITIONS);

	/* Resolve the kernel-text base now -- pre-fork, so every child
	 * inherits the populated cache via COW and the hot-path PC hash
	 * just reads the static.  See kcov_canon_pc / kcov_get_kaslr_base
	 * for what zero (lookup failed) means downstream. */
	(void)kcov_get_kaslr_base();
}

/*
 * Per-child PC-mode bring-up: allocate the dedup table, open and
 * KCOV_INIT_TRACE the PC fd, mmap its trace buffer, and flip kc->active.
 * Returns true on full success; on any failure tears down what it
 * allocated (dedup table, fd, mmap) and returns false so the caller
 * can bail out before the remote/cmp/select-mode phases.
 *
 * Dedup table:  calloc() so post-fork children get their own copy under
 * COW with every slot's generation field starting at 0.  The first
 * kcov_collect() bumps current_generation to 1, so all slots immediately
 * look stale and the table behaves as if just wiped — without paying
 * the per-call memset cost.
 */
static bool kcov_init_child_pc_fd(struct kcov_child *kc)
{
	kc->dedup = calloc(KCOV_DEDUP_SIZE, sizeof(*kc->dedup));
	if (kc->dedup == NULL)
		return false;

	kc->fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (kc->fd < 0)
		goto err_free_dedup;

	if (ioctl(kc->fd, KCOV_INIT_TRACE, KCOV_TRACE_SIZE) < 0) {
		close(kc->fd);
		kc->fd = -1;
		goto err_free_dedup;
	}

	kc->trace_buf = mmap(NULL,
		KCOV_TRACE_SIZE * sizeof(unsigned long),
		PROT_READ | PROT_WRITE, MAP_SHARED,
		kc->fd, 0);

	if (kc->trace_buf == MAP_FAILED) {
		close(kc->fd);
		kc->fd = -1;
		kc->trace_buf = NULL;
		goto err_free_dedup;
	}

	kc->active = true;
	return true;

err_free_dedup:
	free(kc->dedup);
	kc->dedup = NULL;
	return false;
}

/*
 * Probe for KCOV_REMOTE_ENABLE support.  Try a remote enable/disable
 * cycle -- if the ioctl succeeds, the kernel supports it.
 *
 * KCOV_DISABLE is best-effort here: a kernel that accepts the
 * REMOTE_ENABLE but fails the immediate DISABLE leaves the PC fd
 * stuck in enabled state, so we close it and reopen / re-INIT / re-mmap
 * to land back at the same post-pc-fd-setup state.  Any failure in
 * that recovery dance clears kc->active -- the subsequent cmp-fd
 * setup gates on it.
 */
static void kcov_init_child_remote_probe(struct kcov_child *kc,
					 unsigned int child_id)
{
	struct kcov_remote_arg *arg;

	arg = calloc(1, sizeof(*arg));
	if (arg == NULL)
		return;

	arg->trace_mode = KCOV_TRACE_PC;
	arg->area_size = KCOV_TRACE_SIZE;
	arg->num_handles = 0;
	arg->common_handle = KCOV_SUBSYSTEM_COMMON | (child_id + 1);
	if (ioctl(kc->fd, KCOV_REMOTE_ENABLE, arg) == 0) {
		if (ioctl(kc->fd, KCOV_DISABLE, 0) == 0) {
			kc->remote_capable = true;
		} else {
			/* fd stuck in enabled state — close
			 * and reopen to reset. */
			close(kc->fd);
			munmap(kc->trace_buf,
				KCOV_TRACE_SIZE * sizeof(unsigned long));
			kc->trace_buf = NULL;
			kc->fd = open("/sys/kernel/debug/kcov", O_RDWR);
			if (kc->fd < 0 ||
			    ioctl(kc->fd, KCOV_INIT_TRACE, KCOV_TRACE_SIZE) < 0) {
				if (kc->fd >= 0) {
					close(kc->fd);
					kc->fd = -1;
				}
				kc->active = false;
			} else {
				kc->trace_buf = mmap(NULL,
					KCOV_TRACE_SIZE * sizeof(unsigned long),
					PROT_READ | PROT_WRITE, MAP_SHARED,
					kc->fd, 0);
				if (kc->trace_buf == MAP_FAILED) {
					kc->trace_buf = NULL;
					close(kc->fd);
					kc->fd = -1;
					kc->active = false;
				}
			}
		}
	}
	free(arg);
}

/*
 * Second KCOV fd dedicated to KCOV_TRACE_CMP.  Trinity used to
 * mode-toggle the single PC fd into CMP for 1-in-CMP_MODE_RATIO
 * syscalls, which traded a sliver of every-syscall PC coverage for
 * occasional comparison-operand hints.  We now open a dedicated cmp
 * fd here but each child still runs in a single mode for its
 * lifetime -- KCOV_MODE_PC or KCOV_MODE_CMP, picked once below from
 * the cmp_capable + random-draw block -- so the cmp fd is only
 * actually enabled for CMP-mode children.  This per-child split (vs
 * per-syscall toggling) keeps each child's collection loop simple
 * and avoids interleaving PC and CMP reads on the same fd.  Probe
 * enable/disable here so a kernel without KCOV_TRACE_CMP support
 * degrades cleanly to PC-only without disabling the rest of KCOV.
 * Per-CMP-child cost: one extra fd plus KCOV_CMP_BUFFER_SIZE *
 * sizeof(unsigned long) (~2MB) of mmap.
 *
 * Returns true when the cmp setup failed deep enough that the
 * cmp_fd teardown ran -- the caller then skips the F_DUPFD relocate
 * block and goes straight to mode selection (matches the original
 * err_close_cmp -> goto select_mode shortcut).  Returns false on cmp
 * setup success and on cmp-open failure -- both paths originally
 * fell through to the F_DUPFD relocate block.
 */
static bool kcov_init_child_cmp_fd(struct kcov_child *kc)
{
	if (!kc->active)
		return false;

	kc->cmp_fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (kc->cmp_fd < 0) {
		kcov_diag_record(&kcov_shm->cmp_diag.init_open_errno,
			&kcov_shm->cmp_diag.init_open_count, errno);
		return false;
	}

	if (ioctl(kc->cmp_fd, KCOV_INIT_TRACE,
			(unsigned long)KCOV_CMP_BUFFER_SIZE) < 0) {
		kcov_diag_record(&kcov_shm->cmp_diag.init_init_trace_errno,
			&kcov_shm->cmp_diag.init_init_trace_count, errno);
		goto err_close_cmp;
	}

	kc->cmp_trace_buf = mmap(NULL,
		KCOV_CMP_BUFFER_SIZE * sizeof(unsigned long),
		PROT_READ | PROT_WRITE, MAP_SHARED,
		kc->cmp_fd, 0);
	if (kc->cmp_trace_buf == MAP_FAILED) {
		kcov_diag_record(&kcov_shm->cmp_diag.init_mmap_errno,
			&kcov_shm->cmp_diag.init_mmap_count, errno);
		kc->cmp_trace_buf = NULL;
		goto err_close_cmp;
	}

	/* Probe KCOV_TRACE_CMP support.  An older kernel
	 * without CMP returns -ENOTSUPP from ENABLE; tear
	 * down the cmp fd and leave cmp_capable = false. */
	if (ioctl(kc->cmp_fd, KCOV_ENABLE, KCOV_TRACE_CMP) < 0) {
		kcov_diag_record(&kcov_shm->cmp_diag.init_enable_errno,
			&kcov_shm->cmp_diag.init_enable_count, errno);
		goto err_unmap_cmp;
	}
	if (ioctl(kc->cmp_fd, KCOV_DISABLE, 0) < 0) {
		kcov_diag_record(&kcov_shm->cmp_diag.init_disable_errno,
			&kcov_shm->cmp_diag.init_disable_count, errno);
		goto err_unmap_cmp;
	}

	kc->cmp_capable = true;
	track_shared_region((unsigned long)kc->cmp_trace_buf,
		KCOV_CMP_BUFFER_SIZE * sizeof(unsigned long));
	return false;

err_unmap_cmp:
	munmap(kc->cmp_trace_buf,
		KCOV_CMP_BUFFER_SIZE * sizeof(unsigned long));
	kc->cmp_trace_buf = NULL;
err_close_cmp:
	close(kc->cmp_fd);
	kc->cmp_fd = -1;
	/*
	 * CMP probe failed but the PC fd is still active.  The caller
	 * still runs mode selection so this child is counted in
	 * pc_mode_children -- without this, the KCOV CMP MODES diagnostic
	 * silently undercounts PC-mode children on kernels where CMP
	 * support is broken.  cmp_capable is false here, so the
	 * random-pick branch will deterministically choose KCOV_MODE_PC.
	 */
	return true;
}

/*
 * Pick this child's collection mode for its lifetime.  Gated on
 * cmp_capable so a kernel without KCOV_TRACE_CMP (or any failure
 * in the probe above) degrades cleanly to PC-only across the
 * fleet -- KCOV_MODE_CMP is only reachable when the cmp fd is
 * actually usable.  The population mix doesn't need cryptographic
 * uniformity.
 */
static void kcov_init_child_select_mode(struct kcov_child *kc)
{
	if (kc->cmp_capable && rnd_modulo_u32(KCOV_CMP_CHILD_RECIPROCAL) == 0)
		kc->mode = KCOV_MODE_CMP;
	else
		kc->mode = KCOV_MODE_PC;

	if (kc->mode == KCOV_MODE_CMP)
		__atomic_fetch_add(&kcov_shm->cmp_mode_children, 1,
			__ATOMIC_RELAXED);
	else
		__atomic_fetch_add(&kcov_shm->pc_mode_children, 1,
			__ATOMIC_RELAXED);
}

void kcov_init_child(struct kcov_child *kc, unsigned int child_id)
{
	kc->fd = -1;
	kc->trace_buf = NULL;
	kc->cmp_fd = -1;
	kc->cmp_trace_buf = NULL;
	kc->active = false;
	kc->cmp_capable = false;
	kc->cmp_enabled_this_call = false;
	kc->remote_mode = false;
	kc->remote_capable = false;
	kc->mode = KCOV_MODE_PC;
	kc->recovery_attempts = 0;
	kc->cmp_recovery_attempts = 0;
	kc->dedup = NULL;
	kc->current_generation = 0;

	if (kcov_shm == NULL)
		return;

	if (!kcov_init_child_pc_fd(kc))
		return;

	kcov_init_child_remote_probe(kc, child_id);

	/*
	 * Register the kcov ring buffer with the shared-region tracker so
	 * the range_overlaps_shared() guards in the mm-syscall sanitisers
	 * (munmap, mremap, madvise, mprotect) refuse fuzzed addresses that
	 * land inside it.  Without this, fuzzed madvise(MADV_REMOVE, ...)
	 * or madvise(MADV_DONTNEED, ...) on the kcov pages punches their
	 * physical backing out and the next kcov_collect() reads it,
	 * tripping SIGBUS at kcov.c:290 ("Nonexisting physical address").
	 * Done after the remote-probe re-mmap dance so we register the
	 * final, stable address.
	 */
	if (kc->trace_buf != NULL)
		track_shared_region((unsigned long)kc->trace_buf,
				    KCOV_TRACE_SIZE * sizeof(unsigned long));

	/*
	 * Both fds are now stable (remote-probe re-mmap dance done, cmp
	 * setup done).  Relocate them to KCOV_FD_HIGH_BASE so the low
	 * slots they were handed (3, 4, ...) are out of the way of the
	 * fuzzer's pickers.  The mmap regions stay valid across the
	 * close-of-old because they are anchored to the underlying open
	 * file description, not the fd number: a subsequent KCOV_ENABLE
	 * on the new fd reads/writes the same trace buffer.
	 *
	 * Done only on the cmp-setup success path -- the cmp-helper
	 * deeper-failure return skips this block, which just means
	 * kc->fd keeps its original low number for that child and the
	 * registry covers it.  Per-fd failure (EMFILE etc.) is silently
	 * best-effort: keep the original fd and let the registry catch
	 * any picker that targets it.
	 */
	if (!kcov_init_child_cmp_fd(kc)) {
		if (kc->fd >= 0 && (unsigned int) kc->fd < KCOV_FD_HIGH_BASE) {
			int new_fd = fcntl(kc->fd, F_DUPFD_CLOEXEC,
					   (int) KCOV_FD_HIGH_BASE);

			if (new_fd >= 0) {
				close(kc->fd);
				kc->fd = new_fd;
			}
		}
		if (kc->cmp_fd >= 0 && (unsigned int) kc->cmp_fd < KCOV_FD_HIGH_BASE) {
			int new_fd = fcntl(kc->cmp_fd, F_DUPFD_CLOEXEC,
					   (int) KCOV_FD_HIGH_BASE);

			if (new_fd >= 0) {
				close(kc->cmp_fd);
				kc->cmp_fd = new_fd;
			}
		}
	}

	kcov_init_child_select_mode(kc);
}

void kcov_cleanup_child(struct kcov_child *kc)
{
	if (kc->trace_buf != NULL) {
		/*
		 * If a wild write stomped trace_buf with a non-pointer (pid,
		 * small int, scribbled offset) the libc munmap shadow walk
		 * trips on a non-canonical/misaligned address before the
		 * syscall is even issued.  Drop the obviously-bogus value
		 * instead of dispatching it.
		 */
		if (is_corrupt_ptr_shape(kc->trace_buf))
			outputerr("kcov_cleanup_child: skipping munmap on shape-corrupt trace_buf=%p\n",
				  kc->trace_buf);
		else
			munmap(kc->trace_buf, KCOV_TRACE_SIZE * sizeof(unsigned long));
		kc->trace_buf = NULL;
	}
	if (kc->fd >= 0) {
		close(kc->fd);
		kc->fd = -1;
	}
	if (kc->cmp_trace_buf != NULL) {
		if (is_corrupt_ptr_shape(kc->cmp_trace_buf))
			outputerr("kcov_cleanup_child: skipping munmap on shape-corrupt cmp_trace_buf=%p\n",
				  kc->cmp_trace_buf);
		else
			munmap(kc->cmp_trace_buf,
				KCOV_CMP_BUFFER_SIZE * sizeof(unsigned long));
		kc->cmp_trace_buf = NULL;
	}
	if (kc->cmp_fd >= 0) {
		close(kc->cmp_fd);
		kc->cmp_fd = -1;
	}
	if (kc->dedup != NULL) {
		free(kc->dedup);
		kc->dedup = NULL;
	}
	kc->active = false;
	kc->cmp_capable = false;
	kc->cmp_enabled_this_call = false;
}

/*
 * Rebuild a per-child kcov fd that the fuzzer's close-race chain has
 * silently replaced under us.  Called from the enable paths' EBADF
 * branches: we have already paid the diag-record / first-EBADF-capture
 * cost in the caller and are now committing to either recover the slot
 * or hand the child off to the parent reaper.  is_cmp selects which fd
 * pair to rebuild (kc->fd / kc->trace_buf for the PC fd, kc->cmp_fd /
 * kc->cmp_trace_buf for the cmp fd).
 *
 * The sequence mirrors kcov_init_child's per-fd setup -- open, KCOV_-
 * INIT_TRACE, mmap, F_DUPFD_CLOEXEC up to KCOV_FD_HIGH_BASE -- with two
 * deliberate orderings the bare init path does not need:
 *
 *   1. Open the new fd BEFORE closing the old one.  fd_is_protected
 *      reads kc->fd / kc->cmp_fd; if we left either at -1 for the open()
 *      round-trip, a concurrent arg-gen path could substitute the slot
 *      number the kernel is about to hand back to us, reintroducing the
 *      very race we are recovering from.  Open-then-swap keeps the field
 *      pointing at a real fd at every observable instant.
 *
 *   2. Call untrack_shared_region BEFORE munmap on the old buffer.  The
 *      mm-syscall sanitisers gate fuzzed addresses against the shared-
 *      region tracker; tearing the tracker entry down after munmap lets
 *      a concurrent range_overlaps_shared() check see "still rejecting"
 *      for a now-freed mapping, the unsafe direction (see the contract
 *      in include/utils.h).  After the new mmap we re-register so the
 *      sanitisers protect the fresh address too.
 *
 * Returns true on success with kc->fd / kc->trace_buf (or the cmp pair)
 * now pointing at the rebuilt slot.  Returns false on any underlying
 * failure (open / INIT_TRACE / mmap), leaving the old fd and buffer
 * untouched so the caller can decide whether to retry or _exit -- the
 * helper itself never modifies recovery_attempts and never _exit()s.
 */
static bool kcov_recover_fd(struct kcov_child *kc, bool is_cmp)
{
	unsigned long buf_entries = is_cmp
		? (unsigned long)KCOV_CMP_BUFFER_SIZE
		: (unsigned long)KCOV_TRACE_SIZE;
	unsigned long buf_bytes = buf_entries * sizeof(unsigned long);
	int *fd_slot = is_cmp ? &kc->cmp_fd : &kc->fd;
	unsigned long **buf_slot = is_cmp ? &kc->cmp_trace_buf : &kc->trace_buf;
	unsigned long *new_buf;
	int new_fd;

	new_fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (new_fd < 0)
		return false;

	if (ioctl(new_fd, KCOV_INIT_TRACE, buf_entries) < 0) {
		close(new_fd);
		return false;
	}

	new_buf = mmap(NULL, buf_bytes, PROT_READ | PROT_WRITE, MAP_SHARED,
		new_fd, 0);
	if (new_buf == MAP_FAILED) {
		close(new_fd);
		return false;
	}

	/* Park the rebuilt fd above the picker range, same best-effort
	 * relocation kcov_init_child does.  A failed dup just leaves the
	 * fresh fd at its low slot; the protected-fd registry still covers
	 * it via fd_is_protected once we install it below. */
	if ((unsigned int)new_fd < KCOV_FD_HIGH_BASE) {
		int hi_fd = fcntl(new_fd, F_DUPFD_CLOEXEC,
				  (int)KCOV_FD_HIGH_BASE);

		if (hi_fd >= 0) {
			close(new_fd);
			new_fd = hi_fd;
		}
	}

	if (*buf_slot != NULL) {
		untrack_shared_region((unsigned long)*buf_slot, buf_bytes);
		munmap(*buf_slot, buf_bytes);
	}
	if (*fd_slot >= 0)
		close(*fd_slot);

	*fd_slot = new_fd;
	*buf_slot = new_buf;
	track_shared_region((unsigned long)new_buf, buf_bytes);

	return true;
}

void kcov_enable_trace(struct kcov_child *kc)
{
	unsigned int retries = 0;

	if (kc == NULL || !kc->active)
		return;

	__atomic_store_n(&kc->trace_buf[0], 0, __ATOMIC_RELAXED);

	while (ioctl(kc->fd, KCOV_ENABLE, KCOV_TRACE_PC) < 0) {
		if (errno == EINTR && retries < KCOV_ENABLE_EINTR_MAX) {
			retries++;
			__atomic_fetch_add(
				&kcov_shm->pc_diag.pc_enable_eintr_retries,
				1, __ATOMIC_RELAXED);
			continue;
		}
		kcov_diag_record(
			&kcov_shm->pc_diag.pc_enable_errno,
			&kcov_shm->pc_diag.pc_enable_count, errno);
		/* On the very first EBADF observed by any child, snapshot
		 * which fuzzed syscall was in flight (or had just retired)
		 * and what kc->fd held.  CAS-from-zero on first_ebadf_op_nr
		 * is the gate -- subsequent failures see a non-zero slot
		 * and skip the four stores below, so the four fields stay
		 * consistent w.r.t. each other.  op_nr + 1 offsets the
		 * empty-slot sentinel (0) from the legitimate "EBADF on the
		 * very first syscall" reading. */
		if (errno == EBADF) {
			struct childdata *c = this_child();
			unsigned long op_nr = (c != NULL) ? c->op_nr + 1 : 1;
			unsigned long expected = 0;

			if (__atomic_compare_exchange_n(
					&kcov_shm->pc_diag.first_ebadf_op_nr,
					&expected, op_nr, false,
					__ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
				__atomic_store_n(
					&kcov_shm->pc_diag.first_ebadf_pid,
					(unsigned long) mypid(),
					__ATOMIC_RELAXED);
				__atomic_store_n(
					&kcov_shm->pc_diag.first_ebadf_syscall_nr,
					(c != NULL) ? c->syscall.nr : 0,
					__ATOMIC_RELAXED);
				__atomic_store_n(
					&kcov_shm->pc_diag.first_ebadf_fd_value,
					kc->fd, __ATOMIC_RELAXED);
			}

			/* Try to rebuild the vanished fd up to KCOV_-
			 * RECOVERY_MAX times across this slot's lifetime.
			 * The counter resets in kcov_collect() only after a
			 * syscall actually harvests coverage, so a "recover
			 * then immediately re-EBADF" loop consumes the
			 * budget instead of papering it over.  On successful
			 * recovery, re-zero trace_buf[0] (the new mapping
			 * starts uninitialised) and retry the ioctl on the
			 * fresh fd.  On cap exhaustion or failed recovery,
			 * mark the slot dead and _exit() with
			 * KCOV_RECOVERY_EXHAUSTED_EXIT_CODE so the parent's
			 * reaper hands us a clean init_child slot rather
			 * than leaving this child silently degraded.  The
			 * non-zero status is what makes the reap visible to
			 * reap_entry_is_fast_die(); a bare _exit(0) here
			 * would leave the fork-storm circuit breaker inert
			 * for kcov-recovery loops. */
			kc->recovery_attempts++;
			if (kc->recovery_attempts <= KCOV_RECOVERY_MAX &&
			    kcov_recover_fd(kc, false)) {
				__atomic_store_n(&kc->trace_buf[0], 0,
					__ATOMIC_RELAXED);
				continue;
			}
			kc->active = false;
			_exit(KCOV_RECOVERY_EXHAUSTED_EXIT_CODE);
		}
		kc->active = false;
		break;
	}
}

void kcov_enable_cmp(struct kcov_child *kc)
{
	unsigned int retries = 0;

	if (kc == NULL || !kc->cmp_capable)
		return;

	__atomic_store_n(&kc->cmp_trace_buf[0], 0, __ATOMIC_RELAXED);
	while (ioctl(kc->cmp_fd, KCOV_ENABLE, KCOV_TRACE_CMP) < 0) {
		/* Ride out signal storms the same way the PC and remote
		 * paths do -- a single EINTR is not a reason to demote a
		 * previously-probed-good cmp fd and lose CMP coverage for
		 * the rest of this child's lifetime. */
		if (errno == EINTR && retries < KCOV_ENABLE_EINTR_MAX) {
			retries++;
			continue;
		}
		/* Runtime failure on a previously-probed-good fd.  Record
		 * the symptom into cmp_diag for every observation -- with
		 * the recovery loop below the count is no longer one-per-
		 * child, it tracks the true rate of close-race incidents
		 * hitting cmp_fd.  An EBADF means the slot was aliased by
		 * a fuzzed close/dup/close_range; try to rebuild the cmp
		 * fd up to KCOV_RECOVERY_MAX times before giving up.
		 * Mirrors the PC-side recovery in kcov_enable_trace() --
		 * same _exit(KCOV_RECOVERY_EXHAUSTED_EXIT_CODE) bail so
		 * the reaper's fast-die circuit breaker treats CMP-side
		 * exhaustion identically to PC-side.  Non-EBADF errors
		 * retain the pre-existing demote-and-continue semantics:
		 * the cmp-not-supported / cmp-broken-by-the-kernel case
		 * is not a slot-replacement symptom, PC tracing on the
		 * other fd remains valid, so just stop attempting CMP. */
		kcov_diag_record(&kcov_shm->cmp_diag.runtime_enable_errno,
			&kcov_shm->cmp_diag.runtime_enable_count, errno);
		if (errno == EBADF) {
			kc->cmp_recovery_attempts++;
			if (kc->cmp_recovery_attempts <= KCOV_RECOVERY_MAX &&
			    kcov_recover_fd(kc, true)) {
				__atomic_store_n(&kc->cmp_trace_buf[0], 0,
					__ATOMIC_RELAXED);
				continue;
			}
			kc->active = false;
			_exit(KCOV_RECOVERY_EXHAUSTED_EXIT_CODE);
		}
		kc->cmp_capable = false;
		return;
	}
	kc->cmp_enabled_this_call = true;
}

void kcov_enable_remote(struct kcov_child *kc, unsigned int child_id)
{
	struct kcov_remote_arg arg = {0};
	unsigned int retries = 0;
	bool remote_failed = false;

	if (kc == NULL || !kc->active || !kc->remote_capable)
		return;

	__atomic_store_n(&kc->trace_buf[0], 0, __ATOMIC_RELAXED);

	arg.trace_mode = KCOV_TRACE_PC;
	arg.area_size = KCOV_TRACE_SIZE;
	arg.num_handles = 0;
	arg.common_handle = KCOV_SUBSYSTEM_COMMON | (child_id + 1);

	while (ioctl(kc->fd, KCOV_REMOTE_ENABLE, &arg) < 0) {
		if (errno == EINTR && retries < KCOV_ENABLE_EINTR_MAX) {
			retries++;
			__atomic_fetch_add(
				&kcov_shm->pc_diag.remote_enable_eintr_retries,
				1, __ATOMIC_RELAXED);
			continue;
		}
		kcov_diag_record(
			&kcov_shm->pc_diag.remote_enable_errno,
			&kcov_shm->pc_diag.remote_enable_count, errno);
		kc->remote_capable = false;
		remote_failed = true;
		break;
	}

	if (!remote_failed)
		return;

	/* Fall back to per-thread mode if remote failed at runtime. */
	retries = 0;
	while (ioctl(kc->fd, KCOV_ENABLE, KCOV_TRACE_PC) < 0) {
		if (errno == EINTR && retries < KCOV_ENABLE_EINTR_MAX) {
			retries++;
			__atomic_fetch_add(
				&kcov_shm->pc_diag.remote_fallback_pc_enable_eintr_retries,
				1, __ATOMIC_RELAXED);
			continue;
		}
		kcov_diag_record(
			&kcov_shm->pc_diag.pc_enable_errno,
			&kcov_shm->pc_diag.pc_enable_count, errno);
		/* Same recover-or-die logic as kcov_enable_trace: an EBADF
		 * on this branch means the close-race chain killed the PC
		 * fd between the initial remote enable and this fallback.
		 * The remote-enable arm above does not trigger recovery --
		 * its failure flips remote_capable=false and demotes the
		 * child to PC-only, and the PC-only retries (which land
		 * here when EBADF strikes them too) own the fd-rebuild
		 * budget. */
		if (errno == EBADF) {
			kc->recovery_attempts++;
			if (kc->recovery_attempts <= KCOV_RECOVERY_MAX &&
			    kcov_recover_fd(kc, false)) {
				__atomic_store_n(&kc->trace_buf[0], 0,
					__ATOMIC_RELAXED);
				continue;
			}
			kc->active = false;
			_exit(KCOV_RECOVERY_EXHAUSTED_EXIT_CODE);
		}
		kc->active = false;
		return;
	}
	__atomic_fetch_add(&kcov_shm->pc_diag.remote_fallback_to_pc,
			   1, __ATOMIC_RELAXED);
	kc->remote_mode = false;
}

void kcov_disable(struct kcov_child *kc)
{
	if (kc == NULL || !kc->active)
		return;

	/* Mode is fixed per child at init (see kcov_init_child), so only
	 * one of the two fds is ever enabled per syscall.  Branching here
	 * keeps a CMP-mode child from spamming KCOV_DISABLE -EINVAL on the
	 * PC fd every call (and a PC-mode child from spamming it on the cmp
	 * fd).  The kernel's one-`t->kcov`-per-task rule makes this
	 * exclusive: simultaneously enabling both fds returns -EBUSY on
	 * the second enable, so a child only ever has one fd active. */
	if (kc->mode == KCOV_MODE_PC) {
		if (kc->fd >= 0 && kc->trace_buf != NULL) {
			if (ioctl(kc->fd, KCOV_DISABLE, 0) < 0)
				kcov_diag_record(
					&kcov_shm->pc_diag.pc_disable_errno,
					&kcov_shm->pc_diag.pc_disable_count,
					errno);
		}
	} else if (kc->cmp_fd >= 0 && kc->cmp_trace_buf != NULL &&
		   kc->cmp_enabled_this_call) {
		/* cmp_enabled_this_call gate preserves the pre-existing
		 * defence against a runtime KCOV_TRACE_CMP enable failure
		 * mid-run flipping cmp_capable=false — the disable then
		 * knows not to fire on an fd the kernel never enabled. */
		if (ioctl(kc->cmp_fd, KCOV_DISABLE, 0) < 0)
			kcov_diag_record(
				&kcov_shm->pc_diag.pc_disable_errno,
				&kcov_shm->pc_diag.pc_disable_count,
				errno);
		kc->cmp_enabled_this_call = false;
	}
}

/*
 * Open a per-call KCOV bracket around a childop invocation.
 *
 * Returns true if the bracket took ownership of the trace (caller
 * must pair with kcov_bracket_end); false if the bracket was
 * declined and no enable was issued.  Declined cases:
 *
 *   - kc inactive, or shared state not yet allocated.  Defensive in
 *     addition to the call-site have_kcov gate.
 *   - CMP-mode child.  The kernel rejects holding both KCOV_TRACE_PC
 *     and KCOV_TRACE_CMP on the same task with -EBUSY, so the
 *     existing per-syscall CMP enable on this fd is left undisturbed.
 *   - Nested call.  bracket_owned already set means an outer bracket
 *     is in flight; the inner call must skip its own enable/disable
 *     so the outer collect can still observe a full trace.  Refcount-
 *     style nesting would have the inner kcov_collect drain
 *     trace_buf, leaving the outer bracket to harvest an empty buffer
 *     and return zero edges.
 */
bool kcov_bracket_begin(struct kcov_child *kc)
{
	if (kc == NULL || !kc->active || kcov_shm == NULL) {
		/* kcov_shm == NULL on this defensive arm means the per-call
		 * attempt counter at the child.c gate also could not bump,
		 * so skipping the skipped_inactive bump here keeps the
		 * attempts == bracketed + sum(skipped) invariant intact. */
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->childop_kcov_skipped_inactive,
				1, __ATOMIC_RELAXED);
		return false;
	}
	if (kc->mode == KCOV_MODE_CMP) {
		__atomic_fetch_add(&kcov_shm->childop_kcov_skipped_cmp,
			1, __ATOMIC_RELAXED);
		return false;
	}
	if (kc->bracket_owned) {
		__atomic_fetch_add(&kcov_shm->childop_kcov_skipped_nested,
			1, __ATOMIC_RELAXED);
		return false;
	}

	kcov_enable_trace(kc);
	if (!kc->active) {
		/* kcov_enable_trace flipped active=false on ioctl failure;
		 * no enable is live, so don't claim ownership.  Counted as
		 * skipped_inactive so the attempt still balances out against
		 * the begin-side counter. */
		__atomic_fetch_add(&kcov_shm->childop_kcov_skipped_inactive,
			1, __ATOMIC_RELAXED);
		return false;
	}
	kc->bracket_owned = true;
	__atomic_fetch_add(&kcov_shm->childop_kcov_bracketed,
		1, __ATOMIC_RELAXED);
	return true;
}

/*
 * Close the bracket opened by kcov_bracket_begin and harvest the
 * per-call new-edge count via kcov_collect().  op_nr is the synthetic
 * childop identifier (CHILDOP_KCOV_NR_BASE + child_op_type) used to
 * bypass the per_syscall_*[] arrays inside kcov_collect.
 *
 * Returns 0 when this child did not own the bracket (the matching
 * begin returned false), otherwise the number of bucket bits this
 * call freshly set in kcov_shm->bucket_seen.
 */
unsigned long kcov_bracket_end(struct kcov_child *kc,
				unsigned long op_nr)
{
	unsigned long edges_this_call = 0;

	if (kc == NULL || !kc->bracket_owned)
		return 0;

	kcov_disable(kc);
	/* Childops are PC-mode only (kcov_bracket_begin rejects KCOV_MODE_CMP)
	 * and op_nr >= CHILDOP_KCOV_NR_BASE bypasses the per-syscall arrays
	 * inside kcov_collect, so the do32 dimension is unused on this path;
	 * pass false as the conservative default. */
	kcov_collect(kc, (unsigned int)op_nr, false, &edges_this_call);
	kc->bracket_owned = false;
	return edges_this_call;
}

/*
 * Strip the runtime KASLR base from a kernel PC so the bucket index for
 * a given instruction is invariant across reboots of the same kernel
 * build.  kcov_kaslr_base is populated by kcov_init_global from the
 * address of _text in /proc/kallsyms; on systems where that lookup
 * failed it stays zero and this is the identity transform (the run
 * then hashes raw PCs, matching the pre-canonicalisation behaviour).
 *
 * Single point of canonicalisation.  Callers route every PC that lands
 * in bucket_seen[] or the transition map through here exactly once at
 * the head of the kcov_collect() PC walk, then feed the canonical
 * value into pc_canon_to_edge() and pair_to_transition() without
 * re-canonicalising.  scripts/check-static/kcov-canonicalise-pcs.sh
 * enforces both halves of the rule: pc_canon_to_edge() must not call
 * kcov_canon_pc (would double-subtract the base), and any function in
 * kcov.c that calls pc_canon_to_edge() must also call kcov_canon_pc.
 */
static inline unsigned long kcov_canon_pc(unsigned long pc)
{
	return pc - (unsigned long)kcov_kaslr_base;
}

/*
 * Hash an already-canonicalised PC into an edge index.
 *
 * The previous xor-shift mixed too few of the bits in a typical kernel PC.
 * Two PCs that landed within the same cacheline (low 6 bits identical) and
 * shared the same upper bits ended up hashed to indices differing only in
 * the low 7 bits, clustering thousands of distinct PCs into a tiny bitmap
 * range and triggering false coverage saturation.
 *
 * Murmur3's 64-bit finalizer mixes every input bit into every output bit
 * with a single multiply/xor pair per round, which is enough to avoid the
 * cacheline clustering without breaking the PC's locality for the rest of
 * the pipeline.
 */
static inline unsigned int pc_canon_to_edge(unsigned long pc)
{
	pc ^= pc >> 33;
	pc *= 0xff51afd7ed558ccdUL;
	pc ^= pc >> 33;
	pc *= 0xc4ceb9fe1a85ec53UL;
	pc ^= pc >> 33;
	return (unsigned int)(pc & (KCOV_NUM_EDGES - 1));
}

/*
 * Per-syscall/childop entry sentinel for the shadow transition map.
 * The transition hash needs a stable predecessor for the first PC of a
 * trace so two unrelated calls cannot accidentally join across the
 * boundary (call A's last PC feeding call B's first PC would
 * manufacture a transition that never executed).  The sentinel sets
 * bit 63 so it cannot alias any canonicalised kernel PC (after the
 * KASLR-base subtraction those occupy the low 4 GB), with the
 * (nr, do32) pair encoded below the marker so each call site gets its
 * own predecessor.  The do32 dimension matters because a 32-bit-compat
 * entry into the same syscall slot reaches different kernel entry
 * trampolines than the native path.
 */
static inline unsigned long kcov_entry_sentinel(unsigned int nr, bool do32)
{
	return (1UL << 63) | ((unsigned long)do32 << 32) | (unsigned long)nr;
}

/*
 * Hash a (prev_canon_pc, cur_canon_pc) pair into a transition slot
 * index.  Both inputs are already KASLR-canonicalised — the caller
 * (kcov_collect's PC walk) holds the canonical value for the current
 * PC so it can be threaded into both pc_canon_to_edge() and here
 * without re-running kcov_canon_pc.  Rotates cur left by 1 before
 * xoring so the pair (a, b) hashes differently from (b, a) — a
 * forward and a backward edge through the same two basic blocks are
 * distinct transitions.
 */
static inline unsigned int pair_to_transition(unsigned long prev,
					      unsigned long cur)
{
	unsigned long h = prev * 0x9E3779B97F4A7C15UL;

	h ^= (cur << 1) | (cur >> 63);
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdUL;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53UL;
	h ^= h >> 33;
	return (unsigned int)(h & (KCOV_NUM_TRANSITIONS - 1));
}

/*
 * AFL-style hit-count classification.  Returns the bucket index 0..7 for
 * a count >= 1.  Counts of 1, 2, 3 each get their own bucket (loops with
 * very small iteration counts are common and worth distinguishing); larger
 * counts collapse into geometric ranges so a 100-iteration loop and a
 * 90-iteration loop don't fight over distinct novelty events.
 */
static unsigned int bucket_for_count(unsigned int n)
{
	if (n <= 1)
		return 0;
	if (n == 2)
		return 1;
	if (n == 3)
		return 2;
	if (n <= 7)
		return 3;
	if (n <= 15)
		return 4;
	if (n <= 31)
		return 5;
	if (n <= 127)
		return 6;
	return 7;
}

/*
 * Per-call dedup: count how many times this trace has hit a given edge.
 * Returns the updated count (1 on first sight, ++count on repeat).  On
 * probe overflow returns 1, which makes the caller register the hit in
 * bucket 0 — graceful degradation to old "any-hit" semantics for the
 * pathological edge in the pathological call.
 *
 * A slot is treated as empty when its generation field doesn't match the
 * caller's current generation; this lets kcov_collect() invalidate the
 * entire table by bumping a single counter instead of zeroing it per call.
 */
static unsigned int dedup_inc(struct kcov_dedup_slot *dedup, unsigned int edge,
	uint64_t generation, unsigned int nr, bool do32)
{
	unsigned int slot = (edge * 0x9E3779B1U) & KCOV_DEDUP_MASK;
	unsigned int probe;

	for (probe = 0; probe < KCOV_DEDUP_MAX_PROBE; probe++) {
		struct kcov_dedup_slot *s = &dedup[slot];

		if (s->generation != generation) {
			unsigned long observed = probe;
			unsigned long cur = __atomic_load_n(&kcov_shm->dedup_max_probe_seen,
				__ATOMIC_RELAXED);
			while (observed > cur) {
				if (__atomic_compare_exchange_n(&kcov_shm->dedup_max_probe_seen,
						&cur, observed,
						false,
						__ATOMIC_RELAXED,
						__ATOMIC_RELAXED))
					break;
			}
			s->generation = generation;
			s->edge_idx = edge;
			s->count = 1;
			return 1;
		}
		if (s->edge_idx == edge) {
			unsigned long observed = probe;
			unsigned long cur = __atomic_load_n(&kcov_shm->dedup_max_probe_seen,
				__ATOMIC_RELAXED);
			while (observed > cur) {
				if (__atomic_compare_exchange_n(&kcov_shm->dedup_max_probe_seen,
						&cur, observed,
						false,
						__ATOMIC_RELAXED,
						__ATOMIC_RELAXED))
					break;
			}
			s->count++;
			return s->count;
		}
		slot = (slot + 1) & KCOV_DEDUP_MASK;
	}
	__atomic_fetch_add(&kcov_shm->dedup_probe_overflow,
		1, __ATOMIC_RELAXED);
	if (nr < MAX_NR_SYSCALL)
		__atomic_fetch_add(&kcov_shm->per_syscall_diag[nr][do32].dedup_probe_overflow,
			1, __ATOMIC_RELAXED);
	return 1;
}

bool kcov_collect(struct kcov_child *kc, unsigned int nr, bool do32,
		  unsigned long *new_edge_count)
{
	unsigned long count;
	unsigned long idx;
	unsigned long call_nr;
	unsigned long edges_this_call = 0;
	unsigned long local_distinct_pcs = 0;
	unsigned long transitions_this_call = 0;
	bool found_new = false;
	/* Snapshot the mode once: a mid-loop flip from SHADOW to OFF (no
	 * runtime path does this today, but be explicit) cannot leave the
	 * loop body straddling the gate. */
	enum kcov_transition_coverage_mode tcov_mode =
		__atomic_load_n(&kcov_transition_coverage_mode, __ATOMIC_RELAXED);
	/* Seed prev_canon_pc with the per-syscall entry sentinel so the
	 * first PC in this trace has a stable predecessor.  Remote-mode
	 * traces merge coverage copied from remote contexts into the same
	 * buffer; the ordering quality of that merge
	 * is unverified, so transition records from remote-mode calls are
	 * treated as shadow-only by virtue of the whole feature being
	 * shadow-only — no separate gate is needed yet. */
	unsigned long prev_canon_pc = kcov_entry_sentinel(nr, do32);

	if (new_edge_count != NULL)
		*new_edge_count = 0;

	if (!kc->active)
		return false;

	call_nr = __atomic_fetch_add(&kcov_shm->total_calls,
		1, __ATOMIC_RELAXED);

	if (kc->remote_mode)
		__atomic_fetch_add(&kcov_shm->remote_calls,
			1, __ATOMIC_RELAXED);

	count = __atomic_load_n(&kc->trace_buf[0], __ATOMIC_RELAXED);
	if (count >= KCOV_TRACE_SIZE - 1) {
		/* Kernel wanted to record more PCs than the buffer holds; the
		 * tail of this call's coverage was dropped.  Bump a counter so
		 * the post-mortem can show whether KCOV_TRACE_SIZE needs to
		 * grow again. */
		__atomic_fetch_add(&kcov_shm->trace_truncated, 1,
			__ATOMIC_RELAXED);
		if (nr < MAX_NR_SYSCALL) {
			__atomic_fetch_add(&kcov_shm->per_syscall_diag[nr][do32].trace_truncated,
				1, __ATOMIC_RELAXED);
		} else if (nr >= CHILDOP_KCOV_NR_BASE) {
			unsigned long op = nr - CHILDOP_KCOV_NR_BASE;
			if (op < KCOV_CHILDOP_NR_MAX)
				__atomic_fetch_add(
					&kcov_shm->childop_kcov_trace_truncated[op],
					1, __ATOMIC_RELAXED);
		}
		count = KCOV_TRACE_SIZE - 1;
	}

	/* CAS-loop-up the per-syscall trace-size high-water mark using the
	 * post-cap count.  Same shape as the dedup_max_probe_seen update
	 * inside dedup_inc(): read, attempt cmpxchg, retry on lost race. */
	if (nr < MAX_NR_SYSCALL) {
		uint32_t observed = (uint32_t)count;
		uint32_t cur = __atomic_load_n(
			&kcov_shm->per_syscall_diag[nr][do32].max_trace_size,
			__ATOMIC_RELAXED);
		while (observed > cur) {
			if (__atomic_compare_exchange_n(
					&kcov_shm->per_syscall_diag[nr][do32].max_trace_size,
					&cur, observed,
					false,
					__ATOMIC_RELAXED,
					__ATOMIC_RELAXED))
				break;
		}
	}

	/* Reset the recover-on-EBADF attempt counter only when this call
	 * actually harvested PCs.  A successful KCOV_ENABLE that lands on
	 * a syscall hitting zero kernel code (count == 0) is a no-op
	 * recovery -- forgiving the attempt would let the close-race
	 * chain re-burn the budget every iteration without ever making
	 * progress.  See edge case 3 in the recovery design doc. */
	if (count > 0 && kc->recovery_attempts != 0)
		kc->recovery_attempts = 0;

	/*
	 * Invalidate the dedup table by bumping the generation counter — every
	 * slot whose generation doesn't match is implicitly empty.  Counter is
	 * uint64_t so wraparound is unreachable in any plausible run; the
	 * defensive wipe-and-restart-at-1 below stays as a backstop for any
	 * future logic that resets the counter through zero.
	 */
	kc->current_generation++;
	if (kc->current_generation == 0) {
		memset(kc->dedup, 0, KCOV_DEDUP_SIZE * sizeof(*kc->dedup));
		kc->current_generation = 1;
	}

	/* Cache the bucket from the previous loop iteration so a run of
	 * repeat hits on the same edge (common: a tight kernel loop dumps
	 * the same PC dozens of times into the trace buffer) doesn't have
	 * to recompute bucket_for_count() for the prior count.  prev_edge
	 * is set to an unreachable sentinel so the first iteration always
	 * misses the cache and falls back to the explicit recomputation. */
	unsigned int prev_edge = (unsigned int)-1;
	unsigned int prev_bucket = 0;

	for (idx = 0; idx < count; idx++) {
		unsigned long pc_val = __atomic_load_n(&kc->trace_buf[idx + 1],
			__ATOMIC_RELAXED);
		/* Canonicalise once per PC and drive both pc_canon_to_edge
		 * (for the existing PC bitmap) and pair_to_transition (for
		 * the shadow transition map) off the same value.  Routing
		 * through pc_to_edge() instead would re-run kcov_canon_pc on
		 * every PC. */
		unsigned long canon_pc = kcov_canon_pc(pc_val);
		unsigned int edge = pc_canon_to_edge(canon_pc);
		unsigned int local_count = dedup_inc(kc->dedup, edge,
			kc->current_generation, nr, do32);
		unsigned int bucket = bucket_for_count(local_count);
		unsigned char mask, old;

		if (local_count == 1)
			local_distinct_pcs++;

		/* Shadow transition coverage: hash the (prev_canon_pc,
		 * canon_pc) pair into the transition map and bump the
		 * counters on the 0 -> 1 slot transition.  Done before the
		 * bucket-bit short-circuits below so a re-hit of a known PC
		 * still contributes a transition record for the new
		 * predecessor — that is the whole point of the signal (new
		 * route through warm code). */
		if (tcov_mode != KCOV_TRANSITION_COVERAGE_OFF) {
			unsigned int tslot = pair_to_transition(prev_canon_pc,
								canon_pc);
			unsigned char tseen;

			tseen = __atomic_load_n(&kcov_shm->transition_seen[tslot],
				__ATOMIC_RELAXED);
			if (!(tseen & 0x1U)) {
				unsigned char told;

				told = __atomic_fetch_or(
					&kcov_shm->transition_seen[tslot],
					0x1U, __ATOMIC_RELAXED);
				if (!(told & 0x1U)) {
					__atomic_fetch_add(
						&kcov_shm->transition_edges_found,
						1, __ATOMIC_RELAXED);
					__atomic_fetch_add(
						&kcov_shm->transition_distinct_edges,
						1, __ATOMIC_RELAXED);
					transitions_this_call++;
				}
			}
		}
		prev_canon_pc = canon_pc;

		/* Skip the atomic OR when this hit kept us inside the same
		 * bucket as the previous hit on this edge — there is no
		 * possible new bit to set, so the global write is wasted. */
		if (local_count > 1) {
			unsigned int last_bucket = (edge == prev_edge)
				? prev_bucket
				: bucket_for_count(local_count - 1);
			if (bucket == last_bucket) {
				prev_edge = edge;
				prev_bucket = bucket;
				continue;
			}
		}

		mask = (unsigned char)(1U << bucket);

		/* Relaxed-load short-circuit: in saturated runs the bit is
		 * already set the vast majority of the time, so the locked RMW
		 * below is wasted.  A racing peer that also sees clear hits the
		 * fetch_or path and the (!(old & mask)) gate still elects a
		 * single bucket-bit winner. */
		if (__atomic_load_n(&kcov_shm->bucket_seen[edge],
				    __ATOMIC_RELAXED) & mask)
			continue;

		old = __atomic_fetch_or(&kcov_shm->bucket_seen[edge],
			mask, __ATOMIC_RELAXED);

		if (!(old & mask)) {
			__atomic_fetch_add(&kcov_shm->edges_found,
				1, __ATOMIC_RELAXED);
			edges_this_call++;
			found_new = true;
			/* old == 0 means no bucket bit was previously set
			 * for this edge -- a true first sighting.  Bumping a
			 * separate distinct_edges counter only on this
			 * transition keeps the cardinality signal clean of
			 * the bucket-bit churn that drives edges_found, so
			 * the plateau detector can sample a delta that
			 * actually falls to zero on flat runs. */
			if (old == 0)
				__atomic_fetch_add(&kcov_shm->distinct_edges,
					1, __ATOMIC_RELAXED);
		}

		prev_edge = edge;
		prev_bucket = bucket;
	}

	__atomic_fetch_add(&kcov_shm->total_pcs, count, __ATOMIC_RELAXED);

	if (nr < MAX_NR_SYSCALL) {
		__atomic_fetch_add(&kcov_shm->per_syscall_calls[nr],
			1, __ATOMIC_RELAXED);
		if (found_new) {
			/* per_syscall_edges bumps by 1 (call-count semantics --
			 * see the comment on the field in include/kcov.h).  The
			 * real bucket-edge count is surfaced via the
			 * new_edge_count out-param below. */
			__atomic_fetch_add(&kcov_shm->per_syscall_edges[nr],
				1, __ATOMIC_RELAXED);
			__atomic_store_n(&kcov_shm->last_edge_at[nr],
				call_nr, __ATOMIC_RELAXED);
			/* if this call had a cmp_hint
			 * injected into its arg surface (latched in
			 * generate-args.c via credit_cmp_hint_injection),
			 * credit the resulting PC-edge win to the cmp-hint
			 * pipeline at the per-syscall granularity.  The
			 * cmp_hint_injected_this_call latch is owner-only
			 * written by the child generator path that ran just
			 * before this dispatch, so reading it here is a
			 * plain field access -- no atomics needed on the
			 * latch itself.  Parent-context this_child()==NULL
			 * is handled the same way the prior credit path is:
			 * the helper either set the flag (child) or did
			 * nothing (parent), and a NULL child here means no
			 * latch was set so no PC-win is credited. */
			{
				struct childdata *cc = this_child();

				if (cc != NULL &&
				    cc->cmp_hint_injected_this_call)
					__atomic_fetch_add(
						&kcov_shm->per_syscall_cmp_hint_pc_wins[nr],
						1, __ATOMIC_RELAXED);
			}
			/* Bump the per-syscall frontier-edge ring so the
			 * coverage-frontier picker (when active) can bias
			 * selection toward syscalls currently producing fresh
			 * coverage. */
			frontier_record_new_edge(nr);
		} else if (count > 0) {
			/* Kernel executed code for this syscall but every PC
			 * was already in bucket_seen[] (warm-loaded or
			 * earlier-this-run).  Track separately from
			 * per_syscall_edges so cold-skip / anti-prior / picker
			 * consumers can tell a quietly-exercised syscall from
			 * one that has never fired this run. */
			__atomic_fetch_add(
				&kcov_shm->per_syscall_warm_known_hits[nr], 1,
				__ATOMIC_RELAXED);
			__atomic_fetch_add(&kcov_shm->total_warm_known_hits, 1,
				__ATOMIC_RELAXED);
			/* Lazy-seed last_edge_at[nr] from the warm-known hit
			 * stream.  Without this seed, a syscall whose entire
			 * surface is warm-loaded looks indistinguishable from
			 * one that has never executed -- both have
			 * last_edge_at[nr] == 0 -- and the cold-skip /
			 * frontier consumers throttle accordingly.  Use a
			 * compare-exchange-loop-free pattern: read once, set
			 * if zero.  Races between concurrent first-warm-hits
			 * resolve harmlessly to whichever store wins -- both
			 * carry the same semantic "this syscall is alive". */
			if (__atomic_load_n(&kcov_shm->last_edge_at[nr],
					    __ATOMIC_RELAXED) == 0)
				__atomic_store_n(&kcov_shm->last_edge_at[nr],
						 call_nr, __ATOMIC_RELAXED);
		}
		/* Per-call totals into the (nr, do32)-indexed diag slot:
		 * bucket_bits_real mirrors edges_this_call, distinct_pcs is the
		 * count of dedup_inc() first-sight events.  Both are single
		 * relaxed atomics per call (zero-add suppressed) regardless of
		 * found_new — a warm-known call still has a distinct_pcs > 0
		 * contribution that the post-mortem wants visible. */
		if (edges_this_call > 0)
			__atomic_fetch_add(
				&kcov_shm->per_syscall_diag[nr][do32].bucket_bits_real,
				edges_this_call, __ATOMIC_RELAXED);
		if (local_distinct_pcs > 0)
			__atomic_fetch_add(
				&kcov_shm->per_syscall_diag[nr][do32].distinct_pcs,
				local_distinct_pcs, __ATOMIC_RELAXED);
		/* Shadow transition coverage per-syscall accounting.  The
		 * call-count counter (per_syscall_transition_edges) bumps by
		 * 1 for any call that produced ≥ 1 new transition slot — the
		 * top-N stats block uses its delta the same way the PC top-N
		 * uses per_syscall_edges.  The real counter
		 * (per_syscall_transition_edges_real) carries the raw flip
		 * count so a single call that opens a large new region is
		 * not flattened to the same weight as a call that flipped a
		 * single slot. */
		if (transitions_this_call > 0) {
			__atomic_fetch_add(
				&kcov_shm->per_syscall_transition_edges[nr],
				1, __ATOMIC_RELAXED);
			__atomic_fetch_add(
				&kcov_shm->per_syscall_transition_edges_real[nr],
				transitions_this_call, __ATOMIC_RELAXED);
		}
	}

	if (new_edge_count != NULL)
		*new_edge_count = edges_this_call;

	return found_new;
}

unsigned long kcov_collect_cmp(struct kcov_child *kc, unsigned int nr,
			       bool do32, bool is_explorer,
			       int strategy_at_pick)
{
	unsigned long count;
	unsigned long novel;

	if (kc == NULL || !kc->cmp_capable || kc->cmp_trace_buf == NULL)
		return 0;

	count = __atomic_load_n(&kc->cmp_trace_buf[0], __ATOMIC_RELAXED);
	if (count >= KCOV_CMP_RECORDS_MAX) {
		/* Kernel wanted to record more comparisons than the cmp
		 * buffer holds; the tail was dropped.  Mirrors the PC-side
		 * trace_truncated counter. */
		__atomic_fetch_add(&kcov_shm->cmp_trace_truncated, 1,
			__ATOMIC_RELAXED);
		if (nr < MAX_NR_SYSCALL)
			__atomic_fetch_add(&kcov_shm->per_syscall_diag[nr][do32].cmp_trace_truncated,
				1, __ATOMIC_RELAXED);
		count = KCOV_CMP_RECORDS_MAX;
	}

	/* Reset the recover-on-EBADF attempt counter only when this call
	 * actually harvested cmp records.  Mirrors the PC-side reset in
	 * kcov_collect() -- a successful KCOV_ENABLE on cmp_fd that lands
	 * on a syscall harvesting zero records is a no-op recovery, and
	 * forgiving the attempt would let a close-race chain re-burn the
	 * budget every iteration without ever making progress. */
	if (count > 0 && kc->cmp_recovery_attempts != 0)
		kc->cmp_recovery_attempts = 0;

	if (count == 0)
		return 0;

	cmp_hints_collect(kc->cmp_trace_buf, nr, do32);
	novel = bandit_cmp_observe(kc->cmp_trace_buf, nr, do32,
				   is_explorer, strategy_at_pick);

	__atomic_fetch_add(&kcov_shm->cmp_records_collected, count,
		__ATOMIC_RELAXED);

	return novel;
}

unsigned int kcov_syscall_cold_skip_pct(unsigned int nr)
{
	unsigned long edges, calls, edges_total, calls_total, gap;
	unsigned int pct;

	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL)
		return 0;

	/* Fold warm-loaded priors into the per-syscall view so the
	 * saturation cap fires on cross-session evidence the cold-skip
	 * path otherwise has to re-accumulate from scratch every run.
	 * The _prior arrays are frozen at warm-start (see kcov.h) so a
	 * plain read is sufficient -- no atomic needed. */
	edges = __atomic_load_n(&kcov_shm->per_syscall_edges[nr],
		__ATOMIC_RELAXED);
	calls = __atomic_load_n(&kcov_shm->per_syscall_calls[nr],
		__ATOMIC_RELAXED);
	edges_total = edges + kcov_shm->per_syscall_edges_prior[nr];
	calls_total = calls + kcov_shm->per_syscall_calls_prior[nr];

	/* Saturation cap: confirmed dead-weight slot, short-circuit the
	 * graduated path below.  See KCOV_SAT_CAP_CALLS / RATIO comment
	 * in include/kcov.h for the two-branch productivity test. */
	if (edges_total == 0) {
		if (calls_total >= KCOV_SAT_CAP_CALLS)
			return KCOV_SAT_CAP_SKIP_PCT;
	} else if (calls_total / edges_total >= KCOV_SAT_CAP_RATIO) {
		return KCOV_SAT_CAP_SKIP_PCT;
	}

	if (edges == 0) {
		/* Never produced an edge in THIS run.  Until this syscall has
		 * had KCOV_COLD_THRESHOLD attempts of its own, leave it alone —
		 * total_calls grows from every other syscall too, so basing
		 * the cutoff on total_calls would prematurely retire any
		 * syscall that the dispatch loop happens to under-pick.
		 * Once it has clearly had a fair shot, skip aggressively. */
		gap = calls;
	} else {
		unsigned long total, last;

		total = __atomic_load_n(&kcov_shm->total_calls,
			__ATOMIC_RELAXED);
		last = __atomic_load_n(&kcov_shm->last_edge_at[nr],
			__ATOMIC_RELAXED);
		if (total <= last)
			return 0;
		gap = total - last;
	}

	if (gap <= KCOV_COLD_THRESHOLD)
		return 0;

	/* Graduated skip: the further past the threshold, the more we skip.
	 * Each additional KCOV_COLD_THRESHOLD-sized step adds 10 percentage
	 * points on top of the 50% baseline that the old flat heuristic used,
	 * capped at 90% so even the deadest syscall still gets called once
	 * every ~10 attempts in case kernel state changes underneath us. */
	pct = 50 + (unsigned int)((gap / KCOV_COLD_THRESHOLD) * 10);
	if (pct > 90)
		pct = 90;
	return pct;
}

bool kcov_syscall_is_cold(unsigned int nr)
{
	return kcov_syscall_cold_skip_pct(nr) > 0;
}

void kcov_plateau_check(void)
{
	unsigned long edges_now, delta;
	time_t now;

	if (kcov_shm == NULL)
		return;

	now = time(NULL);
	/* Sample distinct_edges, not edges_found.  edges_found increments on
	 * every (edge, bucket) bit-flip including bucket churn on already-
	 * known edges, so its per-window delta stays above threshold on flat
	 * runs and the plateau detector never fires.  distinct_edges
	 * increments once per edge (on bucket_seen[edge] == 0 -> first-bit)
	 * so its delta reflects true new-code discovery and falls to zero
	 * when the fuzzer is wedged. */
	edges_now = __atomic_load_n(&kcov_shm->distinct_edges, __ATOMIC_RELAXED);

	/* Arm the window on the first call so any pre-existing edge count
	 * (e.g. from the warm-up phase before main_loop entry) is not
	 * mis-attributed to the first 10-minute window.
	 *
	 * Companion fields (plateau_window_start, plateau_prev_edges) are
	 * written before the RELEASE-store of plateau_armed so a child
	 * reader that observes plateau_armed=true via the ACQUIRE pair is
	 * guaranteed to also see the seeded companion state. */
	if (!__atomic_load_n(&kcov_shm->plateau_armed, __ATOMIC_RELAXED)) {
		__atomic_store_n(&kcov_shm->plateau_window_start, now,
				 __ATOMIC_RELAXED);
		__atomic_store_n(&kcov_shm->plateau_prev_edges, edges_now,
				 __ATOMIC_RELAXED);
		__atomic_store_n(&kcov_shm->plateau_armed, true,
				 __ATOMIC_RELEASE);
		return;
	}

	if ((now - __atomic_load_n(&kcov_shm->plateau_window_start,
				   __ATOMIC_RELAXED)) < KCOV_PLATEAU_WINDOW_SEC)
		return;

	{
		unsigned long prev_edges =
			__atomic_load_n(&kcov_shm->plateau_prev_edges,
					__ATOMIC_RELAXED);
		delta = (edges_now >= prev_edges) ? edges_now - prev_edges : 0;
	}
	__atomic_store_n(&kcov_shm->plateau_last_window_delta, delta,
			 __ATOMIC_RELAXED);
	__atomic_store_n(&kcov_shm->plateau_prev_edges, edges_now,
			 __ATOMIC_RELAXED);
	__atomic_store_n(&kcov_shm->plateau_window_start, now,
			 __ATOMIC_RELAXED);

	if (delta < KCOV_PLATEAU_ENTER_THRESHOLD) {
		/* Edge-triggered: emit the warning, bump the transition
		 * counter, and fire the auto-response hook only when we cross
		 * from healthy into PLATEAU.  Subsequent ticks while still in
		 * plateau stay silent so the operator's stats.log gets one
		 * line per episode rather than one per 600s window. */
		if (!__atomic_load_n(&kcov_shm->plateau_active,
				     __ATOMIC_ACQUIRE)) {
			/* Set entered_at BEFORE the RELEASE-store of
			 * plateau_active so a child reader pairing an
			 * ACQUIRE-load of plateau_active with a subsequent
			 * read of plateau_entered_at sees the freshly
			 * stamped entry time, not a stale 0 from a prior
			 * clearance. */
			__atomic_store_n(&kcov_shm->plateau_entered_at, now,
					 __ATOMIC_RELAXED);
			__atomic_store_n(&kcov_shm->plateau_active, true,
					 __ATOMIC_RELEASE);
			__atomic_fetch_add(&shm->stats.plateau_entered, 1,
					   __ATOMIC_RELAXED);
			stats_log_write("PLATEAU: edge-discovery rate %lu edges/%ds < enter-threshold (%d) sustained for >=%d minutes (bandit may be in local minimum, consider intervention)\n",
					delta, KCOV_PLATEAU_WINDOW_SEC,
					KCOV_PLATEAU_ENTER_THRESHOLD,
					KCOV_PLATEAU_WINDOW_SEC / 60);
			strategy_plateau_response();
			/* Lock in the current bitmap on plateau entry --
			 * discovery has stalled, so the bucket_seen table
			 * is at its high-water mark for this run.  Snapshot
			 * even if the periodic cadence wouldn't have fired
			 * yet; bypass the gate via a one-shot. */
			kcov_bitmap_maybe_snapshot();
		}
	} else if (delta >= KCOV_PLATEAU_EXIT_THRESHOLD &&
		   __atomic_load_n(&kcov_shm->plateau_active,
				   __ATOMIC_ACQUIRE)) {
		long minutes = (now - __atomic_load_n(
				&kcov_shm->plateau_entered_at,
				__ATOMIC_RELAXED)) / 60;

		/* Hysteresis band: ENTER <= delta < EXIT keeps the current
		 * state (stay plateaued; don't re-arm a healthy run yet).
		 * Only a recovery past the higher EXIT bar clears the flag,
		 * preventing the edge-rate oscillation around ENTER from
		 * flapping plateau_active window-by-window. */
		__atomic_store_n(&kcov_shm->plateau_entered_at, 0,
				 __ATOMIC_RELAXED);
		__atomic_store_n(&kcov_shm->plateau_active, false,
				 __ATOMIC_RELEASE);
		__atomic_fetch_add(&shm->stats.plateau_exited, 1,
				   __ATOMIC_RELAXED);
		stats_log_write("PLATEAU CLEARED: edge-discovery rate %lu edges/%ds >= exit-threshold (%d) (plateau lasted %ld minutes)\n",
				delta, KCOV_PLATEAU_WINDOW_SEC,
				KCOV_PLATEAU_EXIT_THRESHOLD, minutes);
	}
}

/*
 * Warm-start persistence for kcov_shm->bucket_seen[] + edges_found.
 *
 * Layout: a fixed header followed by KCOV_NUM_EDGES bytes of bucket_seen
 * payload.  Atomic .tmp + rename on save mirrors minicorpus.  No
 * __attribute__((packed)) -- the field sequence below is already
 * naturally aligned on the LP64 ABIs trinity targets.
 *
 * Fingerprint: sha256 over /proc/kallsyms with the leading address column
 * stripped from each line.  Two reasons we don't use utsname.release +
 * utsname.version like the other persisted artifacts:
 *
 *   1. The kernel can be rebuilt without bumping either utsname string
 *      (same source tree, same .config, different timestamp); a utsname
 *      fingerprint accepts a stale bitmap whose edges were measured
 *      against a binary with a different inlining / linker layout.
 *
 *   2. /proc/kallsyms shows zeroed addresses to non-root readers
 *      (kptr_restrict), so the file's raw bytes aren't a stable
 *      fingerprint between root and non-root runs of the same trinity
 *      against the same kernel.  Stripping the first whitespace-
 *      delimited token (the address, real or zero) leaves only the
 *      "<type> <name>[ [module]]" stream, which is identical for both
 *      readers and invariant across KASLR vs nokaslr boots of the same
 *      build.
 */
#define KCOV_BITMAP_FILE_MAGIC		0x4B434256U	/* "KCBV" */
/* Version 2 adds distinct_edges to the header.  Files written by
 * version 1 are rejected on load: distinct_edges cannot be reliably
 * reconstructed from bucket_seen[] (a non-zero byte could be the
 * result of a single first-bit transition or of multiple bucket
 * transitions on the same edge across prior sessions), so a
 * legacy-format file is treated as "no warm start available" and
 * the run begins cold.
 *
 * Version 3 appends per-syscall priors (per_syscall_edges and
 * per_syscall_calls of the writing session) after the bucket_seen
 * payload, with a separate priors_crc32 over the concatenated
 * arrays.  Version 2 files reject cleanly on the existing
 * version-mismatch path and the run begins cold; that is fine --
 * the priors are a soft signal and a single cold restart on the
 * format bump costs nothing the bitmap warm-start was already
 * providing.
 *
 * Version 4 added a boot_id guard from /proc/sys/kernel/random/boot_id
 * to reject cross-boot reloads.  Rationale at the time: the kallsyms
 * fingerprint is deliberately KASLR-invariant (right for identity --
 * same kernel image -> same fingerprint regardless of KASLR or
 * kptr_restrict) but bucket_seen[] was hashed from raw runtime PCs,
 * so a KASLR reroll across a reboot left the fingerprint matching yet
 * silently aliased every cached bucket to a different instruction.
 * boot_id papered over that without canonicalising PCs, at the cost
 * of forcing one cold start per reboot even when the kernel hadn't
 * changed.
 *
 * Version 5 fixes that properly: PCs are stripped of the runtime
 * KASLR base (see kcov_canon_pc / kcov_get_kaslr_base) before they
 * hit the bucket_seen[] hash, so the bucket index for an instruction
 * stays put across reboots of the same build.  The boot_id field and
 * its associated machinery are gone; in its place the header carries
 * kaslr_base purely as a load-time consistency gate -- if the file
 * was written with PCs canonicalised but this run can't canonicalise
 * (kallsyms unreadable, _text absent), or vice versa, the bucket
 * indices would silently disagree and the load is refused.  Files
 * written under v4 reject cleanly on the version mismatch, costing
 * one cold start at the format bump.
 *
 * Version 6 appends a per-syscall diag block after the v3 priors
 * blob: per_syscall_diag[MAX_NR_SYSCALL][2] serialised as packed
 * 16-byte records {u64 bucket_bits_real; u64 distinct_pcs;} with
 * the syscall slot as the outer index and the do32 arch dimension
 * as the inner index.  The previously-unused header pad slot is
 * repurposed as diag_crc32 over that block; in v5 files the same
 * slot is always written as zero by the save path and ignored by
 * the load path, so the on-disk header size is unchanged at 88 B
 * and v5 files load on a v6 binary as before -- they just lack
 * the appended diag block.  The block records true per-syscall
 * edge totals (the bucket_bits_real / distinct_pcs counters the
 * hot path already maintains) so offline tooling can rank
 * syscalls by actual edges discovered rather than only by the
 * v3 productive-call counts.
 *
 * Version 7 appends a per-strategy edge-counter block after the v6
 * diag block: pc_edge_calls_by_strategy[NR_STRATEGIES] followed by
 * pc_edge_count_by_strategy[NR_STRATEGIES], each as plain u64
 * little-endian, naturally aligned.  With NR_STRATEGIES == 3 today
 * (HEURISTIC, RANDOM, COVERAGE_FRONTIER -- see include/strategy.h)
 * the block is 6 x 8 = 48 bytes total.  Two new u32s are appended
 * to the header: strat_crc32 (CRC over the strat block) and a
 * reserved pad slot, growing the on-disk header from 88 B to 96 B.
 * v5/v6 files have only 88 B of header on disk; the load path
 * reads the v6-sized header prefix first, validates the version,
 * and reads the extra 8 B of trailer only when hdr.version >= 7,
 * so v5/v6 files continue to warm-load unchanged on a v7 binary.
 * The block records which selection strategy is producing fresh
 * edges across runs, so offline tooling can spot when (for
 * example) STRATEGY_COVERAGE_FRONTIER stops contributing new
 * edges as the bitmap saturates. */
#define KCOV_BITMAP_FILE_VERSION	7U
/* Oldest file-format version this binary will warm-load.  v4 stays
 * rejected (different header size, different PC basis); v5 loads
 * without the v6 diag block or v7 strat block; v6 loads with diag
 * but without strat; v7 loads all three. */
#define KCOV_BITMAP_FILE_MIN_LOAD_VERSION	5U

struct kcov_bitmap_file_header {
	uint32_t magic;
	uint32_t version;
	uint32_t num_edges;
	uint32_t num_buckets;
	uint64_t edges_found;
	uint64_t distinct_edges;
	uint32_t payload_crc32;
	uint32_t diag_crc32;       /* v6: CRC over the appended diag
				    * block.  v5: always zero (pad). */
	uint8_t  kallsyms_sha256[32];
	uint32_t max_nr_syscall;   /* MAX_NR_SYSCALL at save time */
	uint32_t priors_crc32;     /* CRC over both prior arrays */
	uint64_t kaslr_base;       /* Runtime _text base at save time.
				    * Zero means the writer could not
				    * resolve the base and the payload
				    * is hashed from raw PCs.  The load
				    * path rejects when (hdr.kaslr_base
				    * != 0) XOR (current kcov_kaslr_base
				    * != 0) -- a canonical-vs-raw mix
				    * would silently corrupt bucket
				    * lookups. */
	uint32_t strat_crc32;      /* v7: CRC over the appended strat
				    * block.  v5/v6 files lack this
				    * trailer; the loader leaves it
				    * implicit-zero in those cases. */
	uint32_t pad2;             /* v7: reserved for future use,
				    * always written as zero.  Kept so
				    * the on-disk header is u64-aligned
				    * (96 B) and a future block can
				    * repurpose this slot the way
				    * diag_crc32 / strat_crc32 did. */
};

/* On-disk size of the header as written by v5 and v6 binaries (no
 * trailing strat_crc32 / pad2).  The v7 load path reads this prefix
 * first, validates magic+version, then conditionally reads the
 * trailing 8 B only when the file is v7+. */
#define KCOV_BITMAP_HDR_V6_SIZE	88U

_Static_assert(offsetof(struct kcov_bitmap_file_header, strat_crc32) ==
		       KCOV_BITMAP_HDR_V6_SIZE,
	       "v7 trailer must begin exactly at the end of the v6 header");
_Static_assert(sizeof(struct kcov_bitmap_file_header) == 96,
	       "v7 on-disk header is 96 B (v6 prefix + strat_crc32 + pad2)");
/* NR_STRATEGIES is baked into the v7 strat block layout (6 x u64 = 48 B).
 * Bumping it requires a new on-disk format version. */
_Static_assert(NR_STRATEGIES == 3,
	       "v7 strat block layout assumes exactly 3 strategies");

/* On-disk record for a single per_syscall_diag[nr][dim] slot.
 * Packed pair of u64s, naturally aligned, little-endian.  16 B per
 * slot; MAX_NR_SYSCALL * 2 slots = 32 KiB.  Layout is the contract
 * for the external cache-stats reader, so do not reorder. */
struct kcov_per_syscall_diag_ondisk {
	uint64_t bucket_bits_real;
	uint64_t distinct_pcs;
};

/* On-disk strat block (v7), appended after the v6 diag block.  Six
 * contiguous u64s, naturally aligned, little-endian; total 48 B.
 * Field order (do NOT reorder -- the external cache-stats reader
 * matches this byte-for-byte):
 *
 *   bytes  0..7  : pc_edge_calls_by_strategy[0]   (STRATEGY_HEURISTIC)
 *   bytes  8..15 : pc_edge_calls_by_strategy[1]   (STRATEGY_RANDOM)
 *   bytes 16..23 : pc_edge_calls_by_strategy[2]   (STRATEGY_COVERAGE_FRONTIER)
 *   bytes 24..31 : pc_edge_count_by_strategy[0]   (STRATEGY_HEURISTIC)
 *   bytes 32..39 : pc_edge_count_by_strategy[1]   (STRATEGY_RANDOM)
 *   bytes 40..47 : pc_edge_count_by_strategy[2]   (STRATEGY_COVERAGE_FRONTIER)
 *
 * Both arrays carry the strategy_t value as the index.  The block is
 * covered by hdr.strat_crc32 at header offset 88. */
struct kcov_strat_ondisk {
	uint64_t calls[NR_STRATEGIES];
	uint64_t count[NR_STRATEGIES];
};

_Static_assert(sizeof(struct kcov_strat_ondisk) == 48,
	       "v7 strat block is 48 B (6 x u64)");

/*
 * Streaming SHA-256 implementation.  Trinity links no crypto library, so
 * we ship the algorithm here -- compact enough that the fingerprint code
 * doesn't pull in libcrypto for a single user.  Public-domain reference
 * implementation, FIPS 180-4 conformant; produces an identical digest to
 * `openssl dgst -sha256` for any byte stream.
 */
struct sha256_ctx {
	uint32_t state[8];
	uint64_t bitlen;
	uint8_t  buf[64];
	uint32_t buflen;
};

static const uint32_t sha256_k[64] = {
	0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
	0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
	0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
	0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
	0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
	0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
	0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
	0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
	0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
	0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
	0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
	0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
	0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
	0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
	0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
	0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t sha256_rotr(uint32_t x, unsigned int n)
{
	return (x >> n) | (x << (32U - n));
}

static void sha256_block(struct sha256_ctx *c, const uint8_t blk[64])
{
	uint32_t w[64];
	uint32_t a, b, d, e, f, g, h, t1, t2;
	uint32_t cc;
	unsigned int i;

	for (i = 0; i < 16; i++)
		w[i] = ((uint32_t)blk[i*4] << 24) |
		       ((uint32_t)blk[i*4+1] << 16) |
		       ((uint32_t)blk[i*4+2] << 8) |
			(uint32_t)blk[i*4+3];

	for (i = 16; i < 64; i++) {
		uint32_t s0 = sha256_rotr(w[i-15], 7) ^
			      sha256_rotr(w[i-15], 18) ^ (w[i-15] >> 3);
		uint32_t s1 = sha256_rotr(w[i-2], 17) ^
			      sha256_rotr(w[i-2], 19) ^ (w[i-2] >> 10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}

	a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
	e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];

	for (i = 0; i < 64; i++) {
		uint32_t S1 = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t S0 = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22);
		uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);

		t1 = h + S1 + ch + sha256_k[i] + w[i];
		t2 = S0 + mj;
		h = g; g = f; f = e; e = d + t1;
		d = cc; cc = b; b = a; a = t1 + t2;
	}

	c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
	c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

static void sha256_init(struct sha256_ctx *c)
{
	c->state[0] = 0x6a09e667U; c->state[1] = 0xbb67ae85U;
	c->state[2] = 0x3c6ef372U; c->state[3] = 0xa54ff53aU;
	c->state[4] = 0x510e527fU; c->state[5] = 0x9b05688cU;
	c->state[6] = 0x1f83d9abU; c->state[7] = 0x5be0cd19U;
	c->bitlen = 0;
	c->buflen = 0;
}

static void sha256_update(struct sha256_ctx *c, const void *data, size_t len)
{
	const uint8_t *p = data;

	c->bitlen += (uint64_t)len * 8U;
	while (len > 0) {
		size_t take = 64U - c->buflen;

		if (take > len)
			take = len;
		memcpy(c->buf + c->buflen, p, take);
		c->buflen += (uint32_t)take;
		p += take;
		len -= take;
		if (c->buflen == 64U) {
			sha256_block(c, c->buf);
			c->buflen = 0;
		}
	}
}

static void sha256_final(struct sha256_ctx *c, uint8_t out[32])
{
	uint64_t bitlen = c->bitlen;
	unsigned int i;

	c->buf[c->buflen++] = 0x80U;
	if (c->buflen > 56U) {
		memset(c->buf + c->buflen, 0, 64U - c->buflen);
		sha256_block(c, c->buf);
		c->buflen = 0;
	}
	memset(c->buf + c->buflen, 0, 56U - c->buflen);
	for (i = 0; i < 8; i++)
		c->buf[56U + i] = (uint8_t)(bitlen >> ((7U - i) * 8U));
	sha256_block(c, c->buf);

	for (i = 0; i < 8; i++) {
		out[i*4]     = (uint8_t)(c->state[i] >> 24);
		out[i*4 + 1] = (uint8_t)(c->state[i] >> 16);
		out[i*4 + 2] = (uint8_t)(c->state[i] >> 8);
		out[i*4 + 3] = (uint8_t)(c->state[i]);
	}
}

/*
 * Compute the kernel fingerprint by streaming /proc/kallsyms through
 * SHA-256, skipping the leading whitespace-delimited address token on
 * each line.  The address is what kptr_restrict zeroes for non-root
 * readers; everything past it (symbol type, name, optional module) is
 * stable.  Returns true and fills OUT[32] on success; false (with OUT
 * untouched) on any read or open failure.  Caller treats failure as
 * "warm-start disabled this run".
 */
static bool kcov_fingerprint_kernel(uint8_t out[32])
{
	struct sha256_ctx ctx;
	FILE *f;
	char line[4096];

	f = fopen("/proc/kallsyms", "r");
	if (f == NULL)
		return false;

	sha256_init(&ctx);
	while (fgets(line, sizeof(line), f) != NULL) {
		const char *p = line;
		const char *name;
		size_t len;

		/* Skip the address column (one whitespace-delimited token)
		 * and any whitespace that follows.  The remainder -- type,
		 * name, optional [module], trailing newline -- is what we
		 * would consider hashing.  A malformed all-whitespace line
		 * collapses to the empty string and is just skipped. */
		while (*p && *p != ' ' && *p != '\t')
			p++;
		while (*p == ' ' || *p == '\t')
			p++;

		/* Filter to static built-in kernel symbols only.  Trinity's
		 * own fuzzing of bpf(), kprobes, module loading, etc. adds
		 * runtime entries to /proc/kallsyms whose presence (and even
		 * whose names -- BPF JIT entries embed a per-load hash)
		 * differs across runs of the same kernel binary.  If we hash
		 * those, the fingerprint becomes a function of prior fuzz
		 * activity and the warm-start invariant ("same kernel ->
		 * same fingerprint") breaks. */

		/* Module symbols carry a "[module-name]" suffix; static
		 * built-in symbols never do. */
		if (strchr(p, '[') != NULL)
			continue;

		/* Locate the symbol name: skip the single type char and the
		 * whitespace separating it from the name. */
		if (*p == '\0')
			continue;
		name = p + 1;
		while (*name == ' ' || *name == '\t')
			name++;

		/* BPF JIT programs / trampolines appear as bpf_prog_<hash>
		 * and bpf_trampoline_<id>; both vary per load. */
		if (strncmp(name, "bpf_prog_", 9) == 0 ||
		    strncmp(name, "bpf_trampoline_", 15) == 0)
			continue;

		len = strlen(p);
		if (len > 0)
			sha256_update(&ctx, p, len);
	}

	if (ferror(f)) {
		(void)fclose(f);
		return false;
	}
	(void)fclose(f);

	sha256_final(&ctx, out);
	return true;
}

/*
 * Cached fingerprint for this run.  Computed lazily on first save/load
 * call and stashed so the second call doesn't re-stream /proc/kallsyms.
 * fp_valid stays false if the first computation failed; subsequent calls
 * try again (cheap path -- a missing /proc/kallsyms isn't going to come
 * back during the run, but the retry costs only an open() per attempt).
 */
static uint8_t kcov_kernel_fp[32];
static bool    kcov_kernel_fp_valid;

bool kcov_get_kernel_fp(uint8_t out[32])
{
	if (!kcov_kernel_fp_valid) {
		if (!kcov_fingerprint_kernel(kcov_kernel_fp)) {
			output(0, "kcov-bitmap: kcov_fingerprint_kernel failed (/proc/kallsyms unreadable?) -- cold start\n");
			return false;
		}
		kcov_kernel_fp_valid = true;
	}
	memcpy(out, kcov_kernel_fp, 32);
	return true;
}

/*
 * Dirty-bit proxy for kcov_bitmap_save_file().  edges_found increments
 * once per (edge, bucket) bit-flip in kcov_collect(); when it equals the
 * value at the last successful save, the bitmap contents are bit-for-bit
 * identical and the write would just re-serialise the same bytes.
 * Initialised to ULONG_MAX so the first save in a fresh process always
 * fires; subsequently advanced on every successful save and seeded by
 * the warm-start loader so a load-then-immediate-exit cycle skips its
 * end-of-run save.  Parent-private: the only callers of save_file are
 * the parent (end-of-run path in trinity.c and kcov_bitmap_maybe_snapshot
 * from main_loop / kcov_plateau_check).
 */
static unsigned long kcov_bitmap_edges_at_last_save = ULONG_MAX;

bool kcov_bitmap_save_file(const char *path)
{
	struct kcov_bitmap_file_header hdr;
	struct kcov_strat_ondisk strat_blob;
	unsigned long edges_now;
	unsigned char *priors_blob;
	struct kcov_per_syscall_diag_ondisk *diag_blob;
	size_t priors_blob_size;
	size_t one_array_size;
	size_t diag_blob_size;
	char tmppath[PATH_MAX];
	unsigned int nr;
	unsigned int s;
	int fd;
	int ret;

	if (path == NULL || kcov_shm == NULL)
		return false;

	edges_now = __atomic_load_n(&kcov_shm->edges_found, __ATOMIC_RELAXED);
	if (edges_now == kcov_bitmap_edges_at_last_save) {
		output(0, "kcov-bitmap: snapshot skipped, no new edges since last save\n");
		return true;
	}

	one_array_size = (size_t)MAX_NR_SYSCALL * sizeof(unsigned long);
	priors_blob_size = 2 * one_array_size;
	priors_blob = malloc(priors_blob_size);
	if (priors_blob == NULL) {
		output(0, "kcov-bitmap: priors scratch alloc fail (%zu bytes) -- save aborted\n",
		       priors_blob_size);
		return false;
	}
	memcpy(priors_blob, kcov_shm->per_syscall_edges, one_array_size);
	memcpy(priors_blob + one_array_size, kcov_shm->per_syscall_calls,
	       one_array_size);

	/* v6 diag block: pack per_syscall_diag[nr][dim].{bucket_bits_real,
	 * distinct_pcs} into a contiguous 16-B-per-slot array, nr outer,
	 * dim inner.  Read each field with a relaxed atomic load because
	 * children are still bumping these in parallel from the snapshot
	 * path; a torn pair across (bucket_bits_real, distinct_pcs) of
	 * the same slot is harmless since the two are independent
	 * counters and the readers treat them as soft per-syscall
	 * totals. */
	diag_blob_size = (size_t)MAX_NR_SYSCALL * 2 *
			 sizeof(struct kcov_per_syscall_diag_ondisk);
	diag_blob = malloc(diag_blob_size);
	if (diag_blob == NULL) {
		output(0, "kcov-bitmap: diag scratch alloc fail (%zu bytes) -- save aborted\n",
		       diag_blob_size);
		free(priors_blob);
		return false;
	}
	for (nr = 0; nr < MAX_NR_SYSCALL; nr++) {
		unsigned int dim;

		for (dim = 0; dim < 2; dim++) {
			struct kcov_per_syscall_diag *d =
				&kcov_shm->per_syscall_diag[nr][dim];
			struct kcov_per_syscall_diag_ondisk *o =
				&diag_blob[nr * 2 + dim];

			o->bucket_bits_real = __atomic_load_n(
				&d->bucket_bits_real, __ATOMIC_RELAXED);
			o->distinct_pcs = __atomic_load_n(
				&d->distinct_pcs, __ATOMIC_RELAXED);
		}
	}

	/* v7 strat block: pack pc_edge_calls_by_strategy[] then
	 * pc_edge_count_by_strategy[] into a 48 B u64-LE array.  Same
	 * relaxed-atomic-load reasoning as the diag block above --
	 * children are bumping these in parallel from the snapshot
	 * path; the readers treat them as soft per-strategy totals
	 * so a torn pair is benign. */
	memset(&strat_blob, 0, sizeof(strat_blob));
	for (s = 0; s < NR_STRATEGIES; s++) {
		strat_blob.calls[s] = __atomic_load_n(
			&shm->pc_edge_calls_by_strategy[s],
			__ATOMIC_RELAXED);
		strat_blob.count[s] = __atomic_load_n(
			&shm->pc_edge_count_by_strategy[s],
			__ATOMIC_RELAXED);
	}

	memset(&hdr, 0, sizeof(hdr));
	if (!kcov_get_kernel_fp(hdr.kallsyms_sha256)) {
		free(diag_blob);
		free(priors_blob);
		return false;
	}

	hdr.magic = KCOV_BITMAP_FILE_MAGIC;
	hdr.version = KCOV_BITMAP_FILE_VERSION;
	hdr.num_edges = KCOV_NUM_EDGES;
	hdr.num_buckets = KCOV_NUM_BUCKETS;
	hdr.edges_found = edges_now;
	hdr.distinct_edges = __atomic_load_n(&kcov_shm->distinct_edges,
					     __ATOMIC_RELAXED);
	hdr.payload_crc32 = crc32(kcov_shm->bucket_seen,
					      KCOV_NUM_EDGES);
	hdr.max_nr_syscall = MAX_NR_SYSCALL;
	hdr.priors_crc32 = crc32(priors_blob, priors_blob_size);
	hdr.diag_crc32 = crc32(diag_blob, diag_blob_size);
	hdr.strat_crc32 = crc32(&strat_blob, sizeof(strat_blob));
	/* Stamp the canonicalisation mode so the loader can refuse a
	 * canonical-vs-raw mismatch.  Zero means the writer hashed PCs
	 * raw (kallsyms unreadable, _text absent); non-zero is the
	 * writer's runtime _text address and is informational past the
	 * non-zero check -- the loader only cares about the mode bit,
	 * not the specific base, because both sides canonicalise against
	 * their own local base before comparing bucket indices. */
	hdr.kaslr_base = kcov_kaslr_base;

	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
		       path, (int)mypid());
	if (ret < 0 || (size_t)ret >= sizeof(tmppath)) {
		free(diag_blob);
		free(priors_blob);
		return false;
	}

	fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		free(diag_blob);
		free(priors_blob);
		return false;
	}

	/* Neutralise any fuzzer-installed umask so the save mode is 0644. */
	if (fchmod(fd, 0644) != 0) {
		(void)close(fd);
		(void)unlink(tmppath);
		free(diag_blob);
		free(priors_blob);
		return false;
	}

	if (write_all(fd, &hdr, sizeof(hdr)) < 0)
		goto fail;
	if (write_all(fd, kcov_shm->bucket_seen,
				  KCOV_NUM_EDGES) < 0)
		goto fail;
	if (write_all(fd, priors_blob, priors_blob_size) < 0)
		goto fail;
	if (write_all(fd, diag_blob, diag_blob_size) < 0)
		goto fail;
	if (write_all(fd, &strat_blob, sizeof(strat_blob)) < 0)
		goto fail;
	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		(void)unlink(tmppath);
		free(diag_blob);
		free(priors_blob);
		return false;
	}
	if (rename(tmppath, path) != 0) {
		(void)unlink(tmppath);
		free(diag_blob);
		free(priors_blob);
		return false;
	}
	free(diag_blob);
	free(priors_blob);
	kcov_bitmap_edges_at_last_save = edges_now;
	return true;

fail:
	(void)close(fd);
	(void)unlink(tmppath);
	free(diag_blob);
	free(priors_blob);
	return false;
}

bool kcov_bitmap_load_file(const char *path)
{
	struct kcov_bitmap_file_header hdr;
	uint8_t cur_fp[32];
	unsigned char *scratch;
	uint32_t want_crc;
	ssize_t n;
	int fd;

	if (path == NULL || kcov_shm == NULL)
		return false;

	persist_sweep_stale_tmp(path);

	if (!kcov_get_kernel_fp(cur_fp)) {
		output(0, "kcov-bitmap: cannot fingerprint kernel (/proc/kallsyms unavailable) -- warm-start disabled this run\n");
		return false;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			output(0, "kcov-bitmap: no persisted state at %s -- cold start\n",
			       path);
		else
			output(0, "kcov-bitmap: open(%s) failed: %s -- cold start\n",
			       path, strerror(errno));
		return false;
	}

	/* Read only the v6-sized prefix first so a v5/v6 file (88 B
	 * header on disk) still passes the truncation check; the v7
	 * trailer (strat_crc32 + pad2) is read separately below once
	 * the version is known.  Zero the whole struct up front so the
	 * v7 trailer fields stay implicit-zero on v5/v6 files. */
	memset(&hdr, 0, sizeof(hdr));
	n = read_all(fd, &hdr, KCOV_BITMAP_HDR_V6_SIZE);
	if (n != (ssize_t)KCOV_BITMAP_HDR_V6_SIZE) {
		output(0, "kcov-bitmap: header truncated at %s (got %zd, want %u) -- cold start\n",
		       path, n, (unsigned int)KCOV_BITMAP_HDR_V6_SIZE);
		(void)close(fd);
		return false;
	}

	if (hdr.magic != KCOV_BITMAP_FILE_MAGIC) {
		output(0, "kcov-bitmap: file magic 0x%08x != expected 0x%08x at %s -- cold start\n",
		       hdr.magic, KCOV_BITMAP_FILE_MAGIC, path);
		(void)close(fd);
		return false;
	}
	if (hdr.version < KCOV_BITMAP_FILE_MIN_LOAD_VERSION ||
	    hdr.version > KCOV_BITMAP_FILE_VERSION) {
		output(0, "kcov-bitmap: file version %u outside accepted range [%u..%u] at %s -- cold start\n",
		       hdr.version,
		       (unsigned int)KCOV_BITMAP_FILE_MIN_LOAD_VERSION,
		       (unsigned int)KCOV_BITMAP_FILE_VERSION, path);
		(void)close(fd);
		return false;
	}
	/* v7 trailer: 8 B of {strat_crc32, pad2} that v5/v6 binaries
	 * did not write.  Only present (and only read) when the file
	 * itself is v7+; otherwise the prefix above already left both
	 * fields zero. */
	if (hdr.version >= 7U) {
		size_t tail_size = sizeof(hdr) - KCOV_BITMAP_HDR_V6_SIZE;

		n = read_all(fd, (unsigned char *)&hdr +
				 KCOV_BITMAP_HDR_V6_SIZE, tail_size);
		if (n != (ssize_t)tail_size) {
			output(0, "kcov-bitmap: v7 header trailer truncated at %s (got %zd, want %zu) -- cold start\n",
			       path, n, tail_size);
			(void)close(fd);
			return false;
		}
	}
	if (hdr.num_edges != KCOV_NUM_EDGES) {
		output(0, "kcov-bitmap: num_edges %u != expected %u at %s (file built with a different KCOV_NUM_EDGES) -- cold start\n",
		       hdr.num_edges, KCOV_NUM_EDGES, path);
		(void)close(fd);
		return false;
	}
	if (hdr.num_buckets != KCOV_NUM_BUCKETS) {
		output(0, "kcov-bitmap: num_buckets %u != expected %u at %s (file built with a different KCOV_NUM_BUCKETS) -- cold start\n",
		       hdr.num_buckets, KCOV_NUM_BUCKETS, path);
		(void)close(fd);
		return false;
	}
	if (memcmp(hdr.kallsyms_sha256, cur_fp, sizeof(cur_fp)) != 0) {
		output(0, "kcov-bitmap: kernel fingerprint mismatch at %s (kallsyms content differs from when the file was written) -- cold start\n",
		       path);
		(void)close(fd);
		return false;
	}
	/* The on-disk buckets are indexed by canonical PC (raw PC minus
	 * the writer's KASLR base) when hdr.kaslr_base != 0, and by raw
	 * PC otherwise.  This run's hot path applies the same transform
	 * against the local kcov_kaslr_base, so the two must agree on
	 * whether canonicalisation is in effect at all -- any XOR
	 * mismatch means one side is canonical and the other raw, and
	 * the bucket indices would silently disagree.  Both-canonical
	 * (regardless of which base each used) and both-raw are
	 * accepted; the indices line up because each side strips its
	 * own local base. */
	if ((hdr.kaslr_base != 0) != (kcov_kaslr_base != 0)) {
		output(0, "kcov-bitmap: canonicalisation mismatch at %s (file kaslr_base=0x%llx, current=0x%llx) -- refusing stale bitmap, cold start\n",
		       path,
		       (unsigned long long)hdr.kaslr_base,
		       (unsigned long long)kcov_kaslr_base);
		(void)close(fd);
		return false;
	}

	/* Stage into a scratch buffer so a CRC failure doesn't leave the
	 * shared bitmap half-overwritten with garbage. */
	scratch = malloc(KCOV_NUM_EDGES);
	if (scratch == NULL) {
		output(0, "kcov-bitmap: scratch alloc fail (%zu bytes) -- cold start\n",
		       (size_t)KCOV_NUM_EDGES);
		(void)close(fd);
		return false;
	}
	n = read_all(fd, scratch, KCOV_NUM_EDGES);
	if (n != (ssize_t)KCOV_NUM_EDGES) {
		output(0, "kcov-bitmap: payload truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, n, (size_t)KCOV_NUM_EDGES);
		free(scratch);
		(void)close(fd);
		return false;
	}

	want_crc = crc32(scratch, KCOV_NUM_EDGES);
	if (want_crc != hdr.payload_crc32) {
		output(0, "kcov-bitmap: skipping warm-start of %s -- CRC mismatch\n",
		       path);
		free(scratch);
		(void)close(fd);
		return false;
	}

	memcpy(kcov_shm->bucket_seen, scratch, KCOV_NUM_EDGES);
	free(scratch);

	/* Bitmap warm-start has succeeded by this point.  The priors blob
	 * is a soft signal -- any failure mode below logs and falls through
	 * with priors zeroed, but must not invalidate the bitmap load. */
	if (hdr.max_nr_syscall != MAX_NR_SYSCALL) {
		output(0, "kcov-bitmap: priors disabled, max_nr_syscall %u != %u\n",
		       hdr.max_nr_syscall, (unsigned int)MAX_NR_SYSCALL);
	} else {
		size_t one_array_size = (size_t)MAX_NR_SYSCALL *
					sizeof(unsigned long);
		size_t priors_blob_size = 2 * one_array_size;
		unsigned char *priors_blob = malloc(priors_blob_size);

		if (priors_blob == NULL) {
			output(0, "kcov-bitmap: priors scratch alloc fail (%zu bytes) -- priors skipped\n",
			       priors_blob_size);
		} else {
			n = read_all(fd, priors_blob,
						 priors_blob_size);
			if (n != (ssize_t)priors_blob_size) {
				output(0, "kcov-bitmap: priors truncated at %s (got %zd, want %zu) -- priors skipped\n",
				       path, n, priors_blob_size);
			} else {
				uint32_t got_crc;

				got_crc = crc32(priors_blob,
							    priors_blob_size);
				if (got_crc != hdr.priors_crc32) {
					output(0, "kcov-bitmap: priors CRC mismatch at %s -- priors skipped\n",
					       path);
				} else {
					memcpy(kcov_shm->per_syscall_edges_prior,
					       priors_blob, one_array_size);
					memcpy(kcov_shm->per_syscall_calls_prior,
					       priors_blob + one_array_size,
					       one_array_size);
				}
			}
			free(priors_blob);
		}
	}

	/* v6 diag block: per_syscall_diag[nr][dim].{bucket_bits_real,
	 * distinct_pcs} packed as 16 B per slot, nr outer, dim inner.
	 * Soft signal like the priors above -- any failure mode here
	 * logs and falls through with the diag counters left at zero,
	 * but must not invalidate the bitmap load already committed.
	 * v5 (and below) files lack the block; skip on those without
	 * complaint. */
	if (hdr.version >= 6U && hdr.max_nr_syscall == MAX_NR_SYSCALL) {
		size_t diag_blob_size = (size_t)MAX_NR_SYSCALL * 2 *
			sizeof(struct kcov_per_syscall_diag_ondisk);
		struct kcov_per_syscall_diag_ondisk *diag_blob =
			malloc(diag_blob_size);

		if (diag_blob == NULL) {
			output(0, "kcov-bitmap: diag scratch alloc fail (%zu bytes) -- diag skipped\n",
			       diag_blob_size);
		} else {
			n = read_all(fd, diag_blob, diag_blob_size);
			if (n != (ssize_t)diag_blob_size) {
				output(0, "kcov-bitmap: diag truncated at %s (got %zd, want %zu) -- diag skipped\n",
				       path, n, diag_blob_size);
			} else {
				uint32_t got_crc = crc32(diag_blob,
							 diag_blob_size);

				if (got_crc != hdr.diag_crc32) {
					output(0, "kcov-bitmap: diag CRC mismatch at %s -- diag skipped\n",
					       path);
				} else {
					unsigned int nr;

					for (nr = 0; nr < MAX_NR_SYSCALL; nr++) {
						unsigned int dim;

						for (dim = 0; dim < 2; dim++) {
							struct kcov_per_syscall_diag_ondisk *o =
								&diag_blob[nr * 2 + dim];
							struct kcov_per_syscall_diag *d =
								&kcov_shm->per_syscall_diag[nr][dim];

							__atomic_store_n(&d->bucket_bits_real,
									 o->bucket_bits_real,
									 __ATOMIC_RELAXED);
							__atomic_store_n(&d->distinct_pcs,
									 o->distinct_pcs,
									 __ATOMIC_RELAXED);
						}
					}
					output(0, "kcov-bitmap: loaded v6 diag block from %s (CRC OK)\n",
					       path);
				}
			}
			free(diag_blob);
		}
	}

	/* v7 strat block: pc_edge_calls_by_strategy[NR_STRATEGIES]
	 * then pc_edge_count_by_strategy[NR_STRATEGIES], each as
	 * u64 LE -- 48 B total today (NR_STRATEGIES == 3).  Soft
	 * signal like the diag/priors blocks above: a short read or
	 * CRC mismatch logs and falls through with the per-strategy
	 * counters left at whatever they currently hold (typically
	 * zero on a fresh shm), and the bitmap warm-load stays
	 * committed.  v5/v6 files lack the block; skip them quietly. */
	if (hdr.version >= 7U) {
		struct kcov_strat_ondisk strat_blob;

		memset(&strat_blob, 0, sizeof(strat_blob));
		n = read_all(fd, &strat_blob, sizeof(strat_blob));
		if (n != (ssize_t)sizeof(strat_blob)) {
			output(0, "kcov-bitmap: strat truncated at %s (got %zd, want %zu) -- strat skipped\n",
			       path, n, sizeof(strat_blob));
		} else {
			uint32_t got_crc = crc32(&strat_blob,
						 sizeof(strat_blob));

			if (got_crc != hdr.strat_crc32) {
				output(0, "kcov-bitmap: strat CRC mismatch at %s -- strat skipped\n",
				       path);
			} else {
				unsigned int s;

				for (s = 0; s < NR_STRATEGIES; s++) {
					__atomic_store_n(
						&shm->pc_edge_calls_by_strategy[s],
						strat_blob.calls[s],
						__ATOMIC_RELAXED);
					__atomic_store_n(
						&shm->pc_edge_count_by_strategy[s],
						strat_blob.count[s],
						__ATOMIC_RELAXED);
				}
				output(0, "kcov-bitmap: loaded v7 strat block from %s (CRC OK)\n",
				       path);
			}
		}
	}

	(void)close(fd);
	__atomic_store_n(&kcov_shm->edges_found, hdr.edges_found,
			 __ATOMIC_RELAXED);
	__atomic_store_n(&kcov_shm->distinct_edges, hdr.distinct_edges,
			 __ATOMIC_RELAXED);
	/* Snapshot the warm-loaded count so print_stats() can split
	 * displayed coverage into the warm-vs-cold contribution.  Set
	 * exactly here — after the bitmap + edges_found are in place and
	 * before any child has had a chance to discover new coverage — so
	 * a later (edges_found - edges_warm_loaded) subtraction is the
	 * count of edges this run actually discovered itself. */
	__atomic_store_n(&kcov_shm->edges_warm_loaded, hdr.edges_found,
			 __ATOMIC_RELAXED);
	__atomic_store_n(&kcov_shm->distinct_edges_warm_loaded,
			 hdr.distinct_edges, __ATOMIC_RELAXED);
	/* Seed the dirty-bit baseline so a load-then-immediate-exit cycle
	 * skips the redundant end-of-run save. */
	kcov_bitmap_edges_at_last_save = hdr.edges_found;
	output(0, "kcov-bitmap: loaded %lu edges (%lu distinct) from %s\n",
	       (unsigned long)hdr.edges_found,
	       (unsigned long)hdr.distinct_edges, path);
	return true;
}

const char *kcov_bitmap_default_path(void)
{
	static char pathbuf[PATH_MAX];
	const char *xdg = getenv("XDG_CACHE_HOME");
	const char *home = getenv("HOME");
	char dir[PATH_MAX];
	const char *arch;
	char release[256];
	int ret;
	int rfd;
	ssize_t rn;
	char *nl;

#if defined(__x86_64__)
	arch = "x86_64";
#elif defined(__i386__)
	arch = "i386";
#elif defined(__aarch64__)
	arch = "aarch64";
#elif defined(__arm__)
	arch = "arm";
#elif defined(__powerpc64__)
	arch = "ppc64";
#elif defined(__powerpc__)
	arch = "ppc";
#elif defined(__s390x__)
	arch = "s390x";
#elif defined(__mips__)
	arch = "mips";
#elif defined(__sparc__)
	arch = "sparc";
#elif defined(__riscv) || defined(__riscv__)
	arch = "riscv64";
#else
	arch = "unknown";
#endif

	rfd = open("/proc/sys/kernel/osrelease", O_RDONLY);
	if (rfd < 0)
		return NULL;
	rn = read(rfd, release, sizeof(release) - 1);
	(void)close(rfd);
	if (rn <= 0)
		return NULL;
	release[rn] = '\0';
	nl = strchr(release, '\n');
	if (nl != NULL)
		*nl = '\0';
	/* Sanitise: '/' would split the path; replace in place. */
	for (nl = release; *nl; nl++) {
		if (*nl == '/')
			*nl = '_';
	}

	if (xdg && xdg[0] == '/')
		ret = snprintf(dir, sizeof(dir),
			       "%s/trinity/kcov-bitmap", xdg);
	else if (home && home[0] == '/')
		ret = snprintf(dir, sizeof(dir),
			       "%s/.cache/trinity/kcov-bitmap", home);
	else
		return NULL;
	if (ret < 0 || (size_t)ret >= sizeof(dir))
		return NULL;

	{
		char *p;

		for (p = dir + 1; *p; p++) {
			if (*p == '/') {
				*p = '\0';
				if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
					*p = '/';
					return NULL;
				}
				*p = '/';
			}
		}
		if (mkdir(dir, 0755) != 0 && errno != EEXIST)
			return NULL;
	}

	ret = snprintf(pathbuf, sizeof(pathbuf), "%s/%s-%s",
		       dir, arch, release);
	if (ret < 0 || (size_t)ret >= sizeof(pathbuf))
		return NULL;
	return pathbuf;
}

/*
 * Periodic mid-run snapshot trigger.  Called only from parent context
 * (main_loop's stats tick and kcov_plateau_check's plateau-entry
 * branch), so the snapshot state lives in parent-private statics --
 * no CAS race with children to worry about.
 */
static char kcov_bitmap_snapshot_path[PATH_MAX];
static bool kcov_bitmap_snapshot_enabled;
static unsigned long kcov_bitmap_edges_at_last_snapshot;
static time_t kcov_bitmap_last_snapshot_time;

void kcov_bitmap_enable_snapshots(const char *path)
{
	size_t len;

	if (path == NULL)
		return;
	len = strlen(path);
	if (len == 0 || len >= sizeof(kcov_bitmap_snapshot_path))
		return;
	memcpy(kcov_bitmap_snapshot_path, path, len + 1);
	kcov_bitmap_snapshot_enabled = true;
	kcov_bitmap_last_snapshot_time = time(NULL);
}

void kcov_bitmap_maybe_snapshot(void)
{
	unsigned long edges_now;
	time_t now;

	if (!kcov_bitmap_snapshot_enabled || kcov_shm == NULL)
		return;

	edges_now = __atomic_load_n(&kcov_shm->edges_found, __ATOMIC_RELAXED);
	now = time(NULL);

	if (edges_now < kcov_bitmap_edges_at_last_snapshot
			+ KCOV_BITMAP_SNAPSHOT_EDGES &&
	    now < kcov_bitmap_last_snapshot_time
			+ (time_t)KCOV_BITMAP_SNAPSHOT_INTERVAL_SEC)
		return;

	if (kcov_bitmap_save_file(kcov_bitmap_snapshot_path)) {
		kcov_bitmap_edges_at_last_snapshot = edges_now;
		kcov_bitmap_last_snapshot_time = now;
	}
}
