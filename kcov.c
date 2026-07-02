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
#include <limits.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef CONFIG_GUARD_SHARED
#include "signals.h"	/* kcov_protect_recover / kcov_protect_active */
#endif

#include "arch.h"
#include "child.h"
#include "cmp_hints.h"
#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "persist-util.h"
#include "pids.h"
#include "rnd.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "strategy.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/* F_DUPFD_QUERY may be missing on glibcs that predate it; replicate
 * the include/compat.h definition locally so the EBADF chronicle-slot
 * classifier can match the cmd without pulling compat.h (which double-
 * defines struct file_attr against linux/fs.h that struct_catalog.h
 * already pulls into this TU via minicorpus.h). */
#ifndef F_DUPFD_QUERY
#define F_DUPFD_QUERY (1024 + 3)
#endif

/* KCOV ioctl commands (from linux/kcov.h). */
#define KCOV_INIT_TRACE    _IOR('c', 1, unsigned long)
#define KCOV_ENABLE        _IO('c', 100)
#define KCOV_DISABLE       _IO('c', 101)
#define KCOV_REMOTE_ENABLE _IOW('c', 102, struct kcov_remote_arg)

/* Diagnostic coverage-jump breadcrumb -- called from the tail of
 * kcov_collect() once call_nr is known.  Forward-declared so the
 * definition can sit alongside kcov_plateau_check() further down. */
static void kcov_covjump_breadcrumb_maybe(unsigned long call_nr);

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
	CHILDOP_KCOV_ATTR_DUAL;

/* Default is OFF: the childop CMP harvest path is dormant and the
 * childop dispatch surface is byte-identical to a build without the
 * --childop-cmp-harvest knob.  Flipping to ON opens the §3.2 bracket
 * on every CMP-mode child whose dispatch reaches the existing
 * op_uses_outer_bracket gate (see child.c) so childop syscalls routed
 * through trinity_cmp_syscall harvest their CMP operands into the
 * quarantined childop_recent_pools[nr][do32] lane.  See the
 * childop_cmp_harvest_mode enum in include/kcov.h for the per-mode
 * contract. */
enum childop_cmp_harvest_mode childop_cmp_harvest_mode =
	CHILDOP_CMP_HARVEST_OFF;

/* Default is SHADOW: collect into the transition map and surface it
 * through the stats dump, but do not feed deltas into any steering
 * consumer.  See the kcov_transition_coverage_mode enum in include/
 * kcov.h for the contract. */
enum kcov_transition_coverage_mode kcov_transition_coverage_mode =
	KCOV_TRANSITION_COVERAGE_SHADOW;

/* Default is COMBINED: feed the capped transition delta into
 * frontier_cold_weight()'s blend, bandit_record_pull()'s per-arm
 * reward total, and the frontier-edge ring via frontier_record_
 * transition_edge() so syscalls that produce only transitions (a new
 * ordering through warm-known code, no fresh PC bits) still earn live
 * frontier credit.  The shadow-mode A/B prior to this default flip
 * showed the blend weighting frontier-transition syscalls upward an
 * order of magnitude more often than downward (frontier_blend_new_
 * higher vs frontier_blend_new_lower in shm->stats), which is the
 * divergence gate justifying the live promotion.  --kcov-transition-
 * reward=shadow-only and =off remain as rollback paths.  See the
 * kcov_transition_reward_mode enum in include/kcov.h for the full
 * contract. */
enum kcov_transition_reward_mode kcov_transition_reward_mode =
	KCOV_TRANSITION_REWARD_COMBINED;

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
	unsigned int enable_c, disable_c, rt_enable_c, rt_disable_c;
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
	rt_disable_c = __atomic_load_n(&d->runtime_disable_count, __ATOMIC_RELAXED);

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
		if (rt_disable_c && (size_t)n < bufsz) {
			int e = __atomic_load_n(&d->runtime_disable_errno, __ATOMIC_RELAXED);
			n += snprintf(buf + n, bufsz - n, " runtime_disable=%s(%d)/%u",
				errno_name_or("?", e), e, rt_disable_c);
		}
	}

	return n;
}

/*
 * Walk the owning child's child_syscall_ring backward for the most
 * recent fd-mutating syscall (close / dup / dup2 / dup3 / close_range
 * / fcntl(F_DUPFD*)) and return its chronicle slot, or NULL if none
 * is in the ring.  Caller runs inside the owning child (the EBADF
 * latch fires from the child that observed it), so plain loads are
 * sufficient -- the ring is single-producer with the owning child as
 * the sole writer, and no other context mutates these slots.
 *
 * Used only by the one-shot first-EBADF latch (kcov_latch_first_ebadf),
 * which fires from both PC-enable EBADF arms -- kcov_enable_trace and
 * kcov_enable_remote's PC fallback -- to root-cause WHICH fuzzed syscall
 * plausibly aliased the kcov fd the EBADF was observed on.  It is NOT
 * a hot-path helper.
 */
static const struct chronicle_slot *
kcov_find_last_fd_mut_slot(struct childdata *c)
{
	uint32_t head;
	unsigned int i;

	if (c == NULL)
		return NULL;
	head = c->syscall_ring.head;
	for (i = 0; i < CHILD_SYSCALL_RING_SIZE; i++) {
		uint32_t idx = (head - 1 - i) & (CHILD_SYSCALL_RING_SIZE - 1);
		const struct chronicle_slot *s = &c->syscall_ring.recent[idx];
		struct syscallentry *e;

		if (!s->valid)
			continue;
		e = get_syscall_entry(s->nr, s->do32bit);
		if (e == NULL || e->name == NULL)
			continue;
		if (e->is_close_syscall)
			return s;
		if (strcmp(e->name, "dup") == 0 ||
		    strcmp(e->name, "dup2") == 0 ||
		    strcmp(e->name, "dup3") == 0 ||
		    strcmp(e->name, "close_range") == 0)
			return s;
		if (strcmp(e->name, "fcntl") == 0 ||
		    strcmp(e->name, "fcntl64") == 0) {
			unsigned long cmd = s->a2;

			if (cmd == F_DUPFD ||
			    cmd == F_DUPFD_CLOEXEC ||
			    cmd == F_DUPFD_QUERY)
				return s;
		}
	}
	return NULL;
}

/*
 * Closer-only sibling of kcov_find_last_fd_mut_slot.  Same backward
 * walk, but the match set is restricted to the four syscalls that
 * actually close a fd (close / close_range / dup2 / dup3).  dup and
 * fcntl(F_DUPFD*) allocate a new fd without closing an existing one,
 * so the broad walker can return one of them and mask an older real
 * closer further back in the ring -- not useful for naming what
 * killed kc->fd.  This walker addresses that blind spot directly:
 * compare its result to kcov_find_last_fd_mut_slot's and an
 * allocator-mask is immediately obvious.
 *
 * Same single-producer-in-the-owning-child contract as the broad
 * walker -- plain loads suffice.
 */
static const struct chronicle_slot *
kcov_find_last_closer_slot(struct childdata *c)
{
	uint32_t head;
	unsigned int i;

	if (c == NULL)
		return NULL;
	head = c->syscall_ring.head;
	for (i = 0; i < CHILD_SYSCALL_RING_SIZE; i++) {
		uint32_t idx = (head - 1 - i) & (CHILD_SYSCALL_RING_SIZE - 1);
		const struct chronicle_slot *s = &c->syscall_ring.recent[idx];
		struct syscallentry *e;

		if (!s->valid)
			continue;
		e = get_syscall_entry(s->nr, s->do32bit);
		if (e == NULL || e->name == NULL)
			continue;
		if (e->is_close_syscall)
			return s;
		if (strcmp(e->name, "close_range") == 0 ||
		    strcmp(e->name, "dup2") == 0 ||
		    strcmp(e->name, "dup3") == 0)
			return s;
	}
	return NULL;
}

/*
 * Did the captured fd-mut chronicle slot target a protected fd?
 * "Protected" follows the existing fd_is_protected() / lowest_-
 * protected_fd_in_range() registry (the kcov PC / cmp fds, stderr,
 * the stderr capture memfd).  True means the closer was a fuzzed
 * syscall that the existing registry already covers; false means an
 * unaudited code path scribbled the kcov slot and the search for
 * the closer needs to widen.
 */
static bool kcov_chronicle_slot_touched_protected(const struct chronicle_slot *s)
{
	struct syscallentry *e;

	if (s == NULL)
		return false;
	e = get_syscall_entry(s->nr, s->do32bit);
	if (e == NULL || e->name == NULL)
		return false;
	if (strcmp(e->name, "close_range") == 0) {
		/* Unsigned int to mirror the kernel ABI -- a signed
		 * compare would mis-classify an a2 == (unsigned long)-1
		 * (gen_arg_fd exhaustion) as a negative "hi" and skip
		 * the protected-fd check entirely, so the diag would
		 * say "closer did not touch a protected fd" even when
		 * the kernel walked [a1, 0xFFFFFFFF] over the kcov fd. */
		unsigned int lo = (unsigned int) s->a1;
		unsigned int hi = (unsigned int) s->a2;

		if (hi < lo)
			return false;
		return lowest_protected_fd_in_range(lo, hi) >= 0;
	}
	if (strcmp(e->name, "dup2") == 0 || strcmp(e->name, "dup3") == 0)
		return fd_is_protected((int) s->a1) ||
		       fd_is_protected((int) s->a2);
	/* close / dup / fcntl: a1 is the fd that the kernel operates on. */
	return fd_is_protected((int) s->a1);
}

/*
 * Snapshot the child's /proc/self/fd into the caller-supplied buffer
 * via raw getdents64 -- the same shape utils.c::get_num_fds() uses --
 * so the snapshot does not allocate inside libc opendir/readdir on
 * the EBADF path.  Returns the number of fd numbers written, capped
 * at max (an unbounded copy here would
 * convert a busy child's fd table into an unbounded diag-line write).
 * The dirfd used for the walk is filtered out of the returned set so
 * a reader doesn't have to know which fd we transiently allocated.
 */
static unsigned int kcov_snapshot_proc_self_fd(int *fds, unsigned int max)
{
	struct linux_dirent64 {
		uint64_t       d_ino;
		int64_t        d_off;
		unsigned short d_reclen;
		unsigned char  d_type;
		char           d_name[];
	};
	char buf[4096];
	unsigned int n = 0;
	long nread;
	int dirfd;

	if (fds == NULL || max == 0)
		return 0;
	dirfd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd < 0)
		return 0;
	while (n < max &&
	       (nread = syscall(SYS_getdents64, dirfd, buf, sizeof(buf))) > 0) {
		long pos = 0;

		while (pos < nread && n < max) {
			struct linux_dirent64 *de =
				(struct linux_dirent64 *)(buf + pos);
			const char *name = de->d_name;
			char *endp;
			long fdl;

			pos += de->d_reclen;
			if (name[0] == '.' &&
			    (name[1] == '\0' ||
			     (name[1] == '.' && name[2] == '\0')))
				continue;
			errno = 0;
			fdl = strtol(name, &endp, 10);
			if (errno != 0 || *endp != '\0' ||
			    fdl < 0 || fdl > INT_MAX)
				continue;
			if ((int) fdl == dirfd)
				continue;
			fds[n++] = (int) fdl;
		}
	}
	close(dirfd);
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
	{
		unsigned long cr_trunc = __atomic_load_n(
			&d->close_range_protect_truncate_count,
			__ATOMIC_RELAXED);

		if (cr_trunc && (size_t)n < bufsz)
			n += snprintf(buf + n, bufsz - n,
				" close_range_protect_truncate=%lu",
				cr_trunc);
	}
	if (first_op_nr && (size_t)n < bufsz) {
		unsigned long pid = __atomic_load_n(&d->first_ebadf_pid,
			__ATOMIC_RELAXED);
		unsigned int syscall_nr = __atomic_load_n(
			&d->first_ebadf_syscall_nr, __ATOMIC_RELAXED);
		int fd_value = __atomic_load_n(&d->first_ebadf_fd_value,
			__ATOMIC_RELAXED);
		uint64_t generation = __atomic_load_n(
			&d->first_ebadf_generation, __ATOMIC_RELAXED);
		unsigned int last_fd_mut_nr = __atomic_load_n(
			&d->first_ebadf_last_fd_mut_syscall_nr,
			__ATOMIC_RELAXED);
		unsigned char protected_touched = __atomic_load_n(
			&d->first_ebadf_protected_touched, __ATOMIC_RELAXED);
		unsigned int last_closer_nr = __atomic_load_n(
			&d->first_ebadf_last_closer_syscall_nr,
			__ATOMIC_RELAXED);
		unsigned char closer_protected_touched = __atomic_load_n(
			&d->first_ebadf_closer_protected_touched,
			__ATOMIC_RELAXED);
		unsigned char fd_count = __atomic_load_n(
			&d->first_ebadf_proc_fd_count, __ATOMIC_RELAXED);

		/* op_nr was stored as child->op_nr + 1 so the empty-slot
		 * sentinel (0) is distinguishable from a legitimate first-
		 * syscall capture; undo that here for the operator.  The
		 * trailing :gen<G>[:fdmut=nr<N>[/prot]][:closer=nr<N>[/prot]]
		 * [:fds=A,B,C[+]] tokens are the t18-kcov-ebadf-dump richer
		 * fields -- gen is always emitted because zero is a legitimate
		 * kcov-collect epoch; the fdmut, closer and fds tokens are
		 * gated on non-empty so an EBADF that fired with an empty ring
		 * or an unreadable /proc/self/fd doesn't pad the line.  The
		 * trailing "+" after the fd list signals truncation to
		 * KCOV_FIRST_EBADF_PROC_FD_MAX entries.  fdmut and closer are
		 * both emitted (when present) so an allocator-masked-closer
		 * shape is visible at a glance: fdmut names the most recent
		 * fd-mutator (broad set, includes dup / F_DUPFD), closer names
		 * the most recent actual fd-closer (close / close_range /
		 * dup2 / dup3).  fdmut != closer means a benign allocator
		 * was masking the real closer in the broad walk. */
		n += snprintf(buf + n, bufsz - n,
			" first_ebadf=op%lu:pid%lu:nr%u:fd%d:gen%lu",
			first_op_nr - 1, pid, syscall_nr, fd_value,
			(unsigned long) generation);
		if (last_fd_mut_nr && (size_t)n < bufsz)
			n += snprintf(buf + n, bufsz - n,
				":fdmut=nr%u%s",
				last_fd_mut_nr,
				protected_touched ? "/prot" : "");
		if (last_closer_nr && (size_t)n < bufsz)
			n += snprintf(buf + n, bufsz - n,
				":closer=nr%u%s",
				last_closer_nr,
				closer_protected_touched ? "/prot" : "");
		{
			unsigned char recov = __atomic_load_n(
				&d->first_ebadf_recovery_attempts,
				__ATOMIC_RELAXED);
			unsigned char cmp_recov = __atomic_load_n(
				&d->first_ebadf_cmp_recovery_attempts,
				__ATOMIC_RELAXED);

			/* Always emit when EITHER counter is non-zero so the
			 * "EBADF on a rebuilt fd" case is visible at a glance:
			 * recov=0/0 means the original fd died (kcov_recover_fd
			 * cannot be the cause), recov>0 means the EBADF was on
			 * the post-recovery fd (the rebuilt path is the suspect). */
			if ((recov || cmp_recov) && (size_t)n < bufsz)
				n += snprintf(buf + n, bufsz - n,
					":recov=%u/%u", recov, cmp_recov);
		}
		if (fd_count && (size_t)n < bufsz) {
			unsigned int i;

			n += snprintf(buf + n, bufsz - n, ":fds=");
			for (i = 0; i < fd_count && (size_t)n < bufsz; i++) {
				int fd_n = __atomic_load_n(
					&d->first_ebadf_proc_fds[i],
					__ATOMIC_RELAXED);

				n += snprintf(buf + n, bufsz - n, "%s%d",
					i ? "," : "", fd_n);
			}
			if (fd_count >= KCOV_FIRST_EBADF_PROC_FD_MAX &&
			    (size_t)n < bufsz)
				n += snprintf(buf + n, bufsz - n, "+");
		}
	}

	return n;
}

/*
 * One-shot per-process drain of the first-EBADF trap dump.  The
 * kcov_pc_diag_format() summary in the periodic stats line names
 * the closer the chronicle walker found (or didn't); this dump
 * complements it with the full chronicle snapshot + recovery
 * counters captured at latch time, so the operator can name a
 * closer even when ring scroll defeated both walkers.
 *
 * Process-local one-shot via a static bool inside the helper:
 * once the parent's print loop emits the dump, subsequent calls
 * are silent.  Children's print loops never reach here (no parent-
 * side periodic stats inside children), so the one-shot does not
 * need to be cross-process atomic.
 *
 * Returns true if a fresh trap was drained (one or more output()
 * lines emitted), false if the trap is empty (first_ebadf_op_nr
 * still zero) or already drained.
 */
bool kcov_first_ebadf_trap_drain(void)
{
	static bool drained;
	struct kcov_pc_diag *d;
	unsigned long op_nr;
	unsigned long pid;
	unsigned int  syscall_nr;
	int           fd_value;
	uint64_t      generation;
	unsigned char recov, cmp_recov, count;
	unsigned int  i;

	if (drained)
		return false;
	if (kcov_shm == NULL)
		return false;

	d = &kcov_shm->pc_diag;
	op_nr = __atomic_load_n(&d->first_ebadf_op_nr, __ATOMIC_RELAXED);
	if (op_nr == 0)
		return false;

	/* Latch the one-shot first so a re-entrant or racing caller
	 * cannot double-emit even if the loads below take a while. */
	drained = true;

	pid        = __atomic_load_n(&d->first_ebadf_pid,        __ATOMIC_RELAXED);
	syscall_nr = __atomic_load_n(&d->first_ebadf_syscall_nr, __ATOMIC_RELAXED);
	fd_value   = __atomic_load_n(&d->first_ebadf_fd_value,   __ATOMIC_RELAXED);
	generation = __atomic_load_n(&d->first_ebadf_generation, __ATOMIC_RELAXED);
	recov      = __atomic_load_n(&d->first_ebadf_recovery_attempts,
				     __ATOMIC_RELAXED);
	cmp_recov  = __atomic_load_n(&d->first_ebadf_cmp_recovery_attempts,
				     __ATOMIC_RELAXED);
	count      = __atomic_load_n(&d->first_ebadf_chronicle_count,
				     __ATOMIC_RELAXED);

	output(0, "KCOV-EBADF-TRAP: latched op=%lu pid=%lu nr=%u fd=%d gen=%lu recov=%u/%u chronicle=%u/%u\n",
	       op_nr - 1, pid, syscall_nr, fd_value,
	       (unsigned long) generation,
	       (unsigned int) recov, (unsigned int) cmp_recov,
	       (unsigned int) count, KCOV_EBADF_CHRONICLE_MAX);

	if (count > KCOV_EBADF_CHRONICLE_MAX)
		count = KCOV_EBADF_CHRONICLE_MAX;

	/* Walk the full snapshot, newest first.  Slot 0 is the most
	 * recent retired syscall; the real closer that scrolled off
	 * the live ring's tail is somewhere in here even when both
	 * walkers' "most recent <X>" answer disagreed with reality. */
	for (i = 0; i < KCOV_EBADF_CHRONICLE_MAX; i++) {
		const struct kcov_ebadf_chronicle_slot *s =
			&d->first_ebadf_chronicle[i];
		struct syscallentry *e;
		const char *name;

		if (!s->valid)
			continue;
		e = get_syscall_entry(s->nr, s->do32bit ? true : false);
		name = (e != NULL && e->name != NULL) ? e->name : "?";

		output(0, "KCOV-EBADF-TRAP:   [%u] nr=%u(%s%s) a1=0x%lx a2=0x%lx a3=0x%lx ret=0x%lx errno=%s(%d)\n",
			i, s->nr, name,
			s->do32bit ? "/32" : "",
			s->a1, s->a2, s->a3, s->retval,
			errno_name_or("?", s->errno_post),
			s->errno_post);
	}

	return true;
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
uint64_t kcov_kaslr_base;
static bool     kcov_kaslr_base_valid;

/*
 * Read accessor for kcov_kaslr_base, exposed so cross-run-state writers
 * outside kcov.c (e.g. the cmp-hints pool persistence path) can stamp
 * the same value into their on-disk headers and reject a canonical-vs-
 * raw mismatch on load, the way kcov_bitmap_file_header.kaslr_base does
 * for the bitmap.  Returns zero if kcov_init_global has not run or the
 * KASLR base lookup failed -- the "raw PCs this run" sentinel.
 */
uint64_t kcov_kaslr_base_value(void)
{
	return kcov_kaslr_base;
}

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

	if (ioctl(kc->fd, KCOV_INIT_TRACE, (unsigned long)kcov_trace_size) < 0) {
		close(kc->fd);
		kc->fd = -1;
		goto err_free_dedup;
	}

	kc->trace_buf = mmap(NULL,
		(size_t)kcov_trace_size * sizeof(unsigned long),
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
	arg->area_size = kcov_trace_size;
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
				(size_t)kcov_trace_size * sizeof(unsigned long));
			kc->trace_buf = NULL;
			kc->fd = open("/sys/kernel/debug/kcov", O_RDWR);
			if (kc->fd < 0 ||
			    ioctl(kc->fd, KCOV_INIT_TRACE,
				  (unsigned long)kcov_trace_size) < 0) {
				if (kc->fd >= 0) {
					close(kc->fd);
					kc->fd = -1;
				}
				kc->active = false;
			} else {
				kc->trace_buf = mmap(NULL,
					(size_t)kcov_trace_size * sizeof(unsigned long),
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
 * On any failure path the cmp fd is torn down and kc->cmp_fd is left
 * at -1; the PC fd is untouched.  The caller relocates the PC fd
 * unconditionally and the CMP fd only when it survived the probe.
 */
static void kcov_init_child_cmp_fd(struct kcov_child *kc)
{
	if (!kc->active)
		return;

	kc->cmp_fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (kc->cmp_fd < 0) {
		kcov_diag_record(&kcov_shm->cmp_diag.init_open_errno,
			&kcov_shm->cmp_diag.init_open_count, errno);
		return;
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
#ifdef CONFIG_GUARD_SHARED
	track_shared_region_tagged((unsigned long)kc->cmp_trace_buf,
		KCOV_CMP_BUFFER_SIZE * sizeof(unsigned long),
		"kcov-cmp");
	log_buffer_prot_from_proc_maps(
		"kcov_init_child:register-cmp",
		(unsigned long)kc->cmp_trace_buf,
		KCOV_CMP_BUFFER_SIZE * sizeof(unsigned long));
#else
	track_shared_region((unsigned long)kc->cmp_trace_buf,
		KCOV_CMP_BUFFER_SIZE * sizeof(unsigned long));
#endif
	return;

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
	 * tripping SIGBUS on the trace_buf[0] load at the head of
	 * kcov_collect() ("Nonexisting physical address").
	 * Done after the remote-probe re-mmap dance so we register the
	 * final, stable address.
	 */
	if (kc->trace_buf != NULL) {
#ifdef CONFIG_GUARD_SHARED
		track_shared_region_tagged((unsigned long)kc->trace_buf,
			(size_t)kcov_trace_size * sizeof(unsigned long),
			"kcov-pc");
		/* Investigation hook: capture the PC buffer's live VMA
		 * protection right after registration so a setup-side
		 * strip (already non-writable before any sanitiser has
		 * had a chance to fire) is localised to this site rather
		 * than masked into the on-fault diagnostic that runs
		 * much later. */
		log_buffer_prot_from_proc_maps(
			"kcov_init_child:register-pc",
			(unsigned long)kc->trace_buf,
			(size_t)kcov_trace_size * sizeof(unsigned long));
#else
		track_shared_region((unsigned long)kc->trace_buf,
				    (size_t)kcov_trace_size * sizeof(unsigned long));
#endif
	}

	kcov_init_child_cmp_fd(kc);

	/*
	 * Both fds are now stable (remote-probe re-mmap dance done, cmp
	 * setup done or torn down).  Relocate them to KCOV_FD_HIGH_BASE
	 * so the low slots they were handed (3, 4, ...) are out of the
	 * way of the fuzzer's pickers.  The mmap regions stay valid
	 * across the close-of-old because they are anchored to the
	 * underlying open file description, not the fd number: a
	 * subsequent KCOV_ENABLE on the new fd reads/writes the same
	 * trace buffer.
	 *
	 * The PC fd is always relocated; the CMP fd is relocated only
	 * when the CMP probe left one behind (kernels without
	 * KCOV_TRACE_CMP tear it down and leave cmp_fd at -1).  Per-fd
	 * failure (EMFILE etc.) is silently best-effort: keep the
	 * original fd and let the registry catch any picker that
	 * targets it.
	 */
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

	kcov_init_child_select_mode(kc);
}

/*
 * Drain the per-child kcov_child_local_stats counters into the
 * parent_stats aggregate via the child's stats_ring.  Called from
 * kcov_collect() on two triggers ORed together:
 *
 *   (a) a piggyback on the found-new-edge branch -- a syscall that
 *       widened coverage is already paying the dump-side notification
 *       cost, so fold the staged total_calls delta into the same
 *       parent drain cycle;
 *   (b) a fallback cadence cap of KCOV_LOCAL_STATS_FLUSH_SYSCALLS
 *       calls since the last flush, so a workload that goes a long
 *       stretch without finding a new edge still publishes its
 *       per-call accounting in bounded time.
 *
 * Ring-overflow policy mirrors every other stats_ring_enqueue
 * caller: if the ring is full, stats_ring_enqueue() drops the slot
 * and bumps parent_stats.ring_overflow_total -- the staged delta is
 * still zeroed here so the next flush does not double-publish.  The
 * dump path's "total_calls" is best-effort by construction (the
 * pre-existing kcov_shm->total_calls atomic was a relaxed bump
 * anyway), so a dropped batch surfaces as a small undercount with
 * the overflow counter as the diagnostic.
 */
void kcov_child_flush_stats(struct childdata *child)
{
	struct kcov_child_local_stats *ls;
	unsigned long delta;

	if (child == NULL)
		return;
	ls = child->local_stats;
	if (ls == NULL)
		return;

	delta = ls->total_calls;
	if (delta > 0) {
		/* uint32_t delta field on the slot: clamp in the
		 * pathological case where the flush cadence cap was
		 * itself missed (e.g. ring stayed full for so long that
		 * total_calls climbed past UINT32_MAX).  Publish what
		 * fits, leave the remainder staged for the next flush. */
		uint32_t pub = (delta > UINT32_MAX) ? UINT32_MAX
						    : (uint32_t)delta;

		(void) stats_ring_enqueue(child->stats_ring,
					  STATS_FIELD_TOTAL_CALLS, 0, pub);
		ls->total_calls = delta - pub;
	}

	delta = ls->remote_calls;
	if (delta > 0) {
		uint32_t pub = (delta > UINT32_MAX) ? UINT32_MAX
						    : (uint32_t)delta;

		(void) stats_ring_enqueue(child->stats_ring,
					  STATS_FIELD_REMOTE_CALLS, 0, pub);
		ls->remote_calls = delta - pub;
	}

	delta = ls->total_pcs;
	if (delta > 0) {
		/* total_pcs is a +count batch at the bump site, so a
		 * single flush can carry a much larger residual than the
		 * +1-per-call counters above; the same UINT32_MAX clamp
		 * still bounds the slot field and keeps the remainder
		 * staged. */
		uint32_t pub = (delta > UINT32_MAX) ? UINT32_MAX
						    : (uint32_t)delta;

		(void) stats_ring_enqueue(child->stats_ring,
					  STATS_FIELD_TOTAL_PCS, 0, pub);
		ls->total_pcs = delta - pub;
	}

	delta = ls->total_warm_known_hits;
	if (delta > 0) {
		uint32_t pub = (delta > UINT32_MAX) ? UINT32_MAX
						    : (uint32_t)delta;

		(void) stats_ring_enqueue(child->stats_ring,
					  STATS_FIELD_WARM_KNOWN_HITS, 0, pub);
		ls->total_warm_known_hits = delta - pub;
	}

	ls->local_syscalls_since_flush = 0;
}

/*
 * Fallback flush cadence: bump local_syscalls_since_flush every
 * kcov_collect() call and force a flush once this many syscalls have
 * elapsed without one.  Picked so the parent's per-iteration drain
 * still sees a non-stale total_calls under a workload that goes long
 * stretches without finding a new edge; the found-new piggyback
 * keeps the common-case latency near zero.
 */
#define KCOV_LOCAL_STATS_FLUSH_SYSCALLS 4096u

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
			munmap(kc->trace_buf,
				(size_t)kcov_trace_size * sizeof(unsigned long));
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
		: (unsigned long)kcov_trace_size;
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
#ifdef CONFIG_GUARD_SHARED
	track_shared_region_tagged((unsigned long)new_buf, buf_bytes,
				   is_cmp ? "kcov-cmp" : "kcov-pc");
#else
	track_shared_region((unsigned long)new_buf, buf_bytes);
#endif

	return true;
}

/*
 * One-shot snapshot of the in-flight context the first time any child
 * observes EBADF from a PC-enable ioctl.  CAS-from-zero on
 * first_ebadf_op_nr is the gate -- subsequent failures (from this
 * caller OR the remote-fallback caller) see a non-zero slot and skip
 * the stores below, so the captured fields stay consistent w.r.t.
 * each other and the latch fires at most once across both PC-enable
 * arms.  op_nr + 1 offsets the empty-slot sentinel (0) from the
 * legitimate "EBADF on the very first syscall" reading.
 */
static void kcov_latch_first_ebadf(struct kcov_child *kc, struct childdata *c)
{
	unsigned long op_nr = (c != NULL) ? c->op_nr + 1 : 1;
	unsigned long expected = 0;

	if (!__atomic_compare_exchange_n(
			&kcov_shm->pc_diag.first_ebadf_op_nr,
			&expected, op_nr, false,
			__ATOMIC_RELAXED, __ATOMIC_RELAXED))
		return;

	{
		const struct chronicle_slot *fdm =
			kcov_find_last_fd_mut_slot(c);
		const struct chronicle_slot *closer =
			kcov_find_last_closer_slot(c);
		unsigned int last_fd_mut_nr =
			(fdm != NULL) ? fdm->nr : 0;
		unsigned char protected_touched = (fdm != NULL &&
			kcov_chronicle_slot_touched_protected(fdm))
			? 1 : 0;
		unsigned int last_closer_nr =
			(closer != NULL) ? closer->nr : 0;
		unsigned char closer_protected_touched = (closer != NULL &&
			kcov_chronicle_slot_touched_protected(closer))
			? 1 : 0;
		int fd_snapshot[KCOV_FIRST_EBADF_PROC_FD_MAX];
		unsigned int snap_count =
			kcov_snapshot_proc_self_fd(fd_snapshot,
				KCOV_FIRST_EBADF_PROC_FD_MAX);
		unsigned int i;

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
		/* Per-child kcov-collect epoch so the dump
		 * pins the snapshot to a specific generation
		 * window -- a slot that lived through N
		 * kcov_collect() bumps before its kcov fd
		 * vanished reads N here, isolating the "fd
		 * died on the very first call" shape from
		 * the late-life shape. */
		__atomic_store_n(
			&kcov_shm->pc_diag.first_ebadf_generation,
			kc->current_generation, __ATOMIC_RELAXED);
		__atomic_store_n(
			&kcov_shm->pc_diag.first_ebadf_last_fd_mut_syscall_nr,
			last_fd_mut_nr, __ATOMIC_RELAXED);
		__atomic_store_n(
			&kcov_shm->pc_diag.first_ebadf_protected_touched,
			protected_touched, __ATOMIC_RELAXED);
		__atomic_store_n(
			&kcov_shm->pc_diag.first_ebadf_last_closer_syscall_nr,
			last_closer_nr, __ATOMIC_RELAXED);
		__atomic_store_n(
			&kcov_shm->pc_diag.first_ebadf_closer_protected_touched,
			closer_protected_touched, __ATOMIC_RELAXED);
		__atomic_store_n(
			&kcov_shm->pc_diag.first_ebadf_recovery_attempts,
			(unsigned char) kc->recovery_attempts,
			__ATOMIC_RELAXED);
		__atomic_store_n(
			&kcov_shm->pc_diag.first_ebadf_cmp_recovery_attempts,
			(unsigned char) kc->cmp_recovery_attempts,
			__ATOMIC_RELAXED);
		/* Snapshot the owning child's chronicle ring newest-first
		 * so the parent-side trap dumper can name the real closer
		 * even when ring scroll defeated the closer walker above.
		 * Plain stores -- this is the CAS winner inside the
		 * owning child and no other context touches these slots. */
		if (c != NULL) {
			uint32_t head = c->syscall_ring.head;
			unsigned int j;
			unsigned int populated = 0;

			for (j = 0; j < KCOV_EBADF_CHRONICLE_MAX; j++) {
				uint32_t idx =
					(head - 1 - j) &
					(CHILD_SYSCALL_RING_SIZE - 1);
				const struct chronicle_slot *s =
					&c->syscall_ring.recent[idx];
				struct kcov_ebadf_chronicle_slot *out =
					&kcov_shm->pc_diag.first_ebadf_chronicle[j];

				out->a1         = s->a1;
				out->a2         = s->a2;
				out->a3         = s->a3;
				out->retval     = s->retval;
				out->nr         = s->nr;
				out->errno_post = s->errno_post;
				out->do32bit    = s->do32bit ? 1 : 0;
				out->valid      = s->valid ? 1 : 0;
				if (s->valid)
					populated++;
			}
			__atomic_store_n(
				&kcov_shm->pc_diag.first_ebadf_chronicle_count,
				(unsigned char) populated,
				__ATOMIC_RELAXED);
		}
		for (i = 0; i < snap_count; i++)
			__atomic_store_n(
				&kcov_shm->pc_diag.first_ebadf_proc_fds[i],
				fd_snapshot[i],
				__ATOMIC_RELAXED);
		/* Publish proc_fd_count last so a reader
		 * that observes a non-zero count is
		 * guaranteed the corresponding fd entries
		 * are visible (relaxed matches the rest of
		 * the latch -- the dump reader runs long
		 * after the CAS winner has retired). */
		__atomic_store_n(
			&kcov_shm->pc_diag.first_ebadf_proc_fd_count,
			(unsigned char) snap_count,
			__ATOMIC_RELAXED);
	}
}

#ifdef CONFIG_GUARD_SHARED
/*
 * Run the on-fault diagnostic dump for a kcov_enable_trace() reset
 * fault.  The reset store at the head of kcov_enable_trace runs under
 * sigsetjmp(kcov_protect_recover); when child_fault_handler catches a
 * SIGSEGV/SIGBUS with kcov_protect_active set it siglongjmp's back
 * and we end up here.  The dump itemises everything the spec asked
 * for so the post-hoc analysis can pin which actor stripped the
 * buffer:
 *
 *   1. Buffer addr + size, both branches (PC vs CMP fallback).
 *   2. Live VMA prot from /proc/self/maps -- the smoking-gun for any
 *      caller (sanitiser miss, internal mprotect, external syscall)
 *      that ended up actually flipping the page.
 *   3. Registration-still-present check -- catches the path where an
 *      untrack_shared_region() fired but the matching protection
 *      restore did not.
 *   4. The per-child audit ring's last ~16 disagreements -- the
 *      accelerator desync history that immediately preceded the
 *      fault, so the offending mm-sanitiser call site is named in
 *      the same log block as the fault itself.
 *
 * Bumps a counter on the shared kcov diag and _exit()s with
 * KCOV_PROT_FAULT_EXIT_CODE so the parent reaper distinguishes a
 * protection-strip fault from a clean exit / recovery-exhausted
 * bail.  Does NOT attempt silent recovery -- masking the fault is
 * the exact behaviour the audit is here to expose.
 */
static void kcov_enable_trace_dump_fault(struct kcov_child *kc, bool is_cmp)
{
	unsigned long buf_addr = (unsigned long)
		(is_cmp ? kc->cmp_trace_buf : kc->trace_buf);
	unsigned long buf_bytes = is_cmp
		? KCOV_CMP_BUFFER_SIZE * sizeof(unsigned long)
		: (size_t)kcov_trace_size * sizeof(unsigned long);
	const char *origin = is_cmp ? "kcov-cmp" : "kcov-pc";

	outputerr("kcov_enable_trace: protection-strip fault on %s buffer "
		  "addr=0x%lx size=0x%lx\n", origin, buf_addr, buf_bytes);
	log_buffer_prot_from_proc_maps("kcov_enable_trace:on-fault",
				       buf_addr, buf_bytes);
	if (kcov_registration_still_present(buf_addr, buf_bytes, origin))
		outputerr("kcov_enable_trace: %s registration STILL present "
			  "in shared_regions[]\n", origin);
	else
		outputerr("kcov_enable_trace: %s registration MISSING from "
			  "shared_regions[] -- untrack/munmap path took it\n",
			  origin);
	kcov_audit_ring_dump("kcov_enable_trace:on-fault");

	if (kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->pc_diag.pc_enable_count, 1,
				   __ATOMIC_RELAXED);

	kc->active = false;
	_exit(KCOV_PROT_FAULT_EXIT_CODE);
}
#endif	/* CONFIG_GUARD_SHARED */

void kcov_enable_trace(struct kcov_child *kc)
{
	/*
	 * volatile under CONFIG_GUARD_SHARED because the sigsetjmp/
	 * longjmp pair inserted below crosses this scope; ISO C 7.13.2.1
	 * only guarantees post-longjmp values for objects of volatile-
	 * qualified type, and gcc -Wclobbered would otherwise flag it.
	 * Cost is one stack reload per ioctl loop iteration, well below
	 * the cost of the ioctl itself.  Plain unsigned int in the no-
	 * guard build keeps the byte image unchanged.
	 */
#ifdef CONFIG_GUARD_SHARED
	volatile unsigned int retries = 0;
#else
	unsigned int retries = 0;
#endif

	if (kc == NULL || !kc->active)
		return;

#ifdef CONFIG_GUARD_SHARED
	/*
	 * On-fault diagnostic.  The trace_buf[0]=0 reset below is
	 * supposed to be safe: the buffer is registered with origin
	 * "kcov-pc" in shared_regions[] and the mm-sanitiser overlap
	 * gates are supposed to refuse fuzzed addresses that touch it.
	 * Yet runs reproducibly take SEGV_ACCERR/SIGBUS on the store,
	 * so some path is silently stripping PROT_WRITE between
	 * registration and use.  Install a sigsetjmp before each store
	 * attempt so child_fault_handler siglongjmp's back here on a
	 * real (si_code > 0) SIGSEGV/SIGBUS while kcov_protect_active
	 * is set -- the dump helper then logs everything the spec asks
	 * for and _exit()s with KCOV_PROT_FAULT_EXIT_CODE.  No silent
	 * recovery; masking the fault is the bug the audit is here to
	 * find.
	 */
	if (sigsetjmp(kcov_protect_recover, 1) != 0) {
		kcov_protect_active = 0;
		kcov_enable_trace_dump_fault(kc, false);
		/* not reached */
	}
	kcov_protect_active = 1;
	__atomic_store_n(&kc->trace_buf[0], 0, __ATOMIC_RELAXED);
	kcov_protect_active = 0;
#else
	__atomic_store_n(&kc->trace_buf[0], 0, __ATOMIC_RELAXED);
#endif

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
		if (errno == EBADF) {
			kcov_latch_first_ebadf(kc, this_child());

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

void kcov_enable_remote(struct kcov_child *kc, unsigned int child_id, unsigned int nr)
{
	struct kcov_remote_arg arg = {0};
	unsigned int retries = 0;
	bool remote_failed = false;

	if (kc == NULL || !kc->active || !kc->remote_capable)
		return;

	__atomic_store_n(&kc->trace_buf[0], 0, __ATOMIC_RELAXED);

	arg.trace_mode = KCOV_TRACE_PC;
	arg.area_size = kcov_trace_size;
	arg.num_handles = 0;
	arg.common_handle = KCOV_SUBSYSTEM_COMMON | (child_id + 1);

	if (nr < MAX_NR_SYSCALL)
		__atomic_fetch_add(&kcov_shm->remote_enable_requested[nr], 1,
				   __ATOMIC_RELAXED);

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

	if (!remote_failed) {
		if (nr < MAX_NR_SYSCALL)
			__atomic_fetch_add(&kcov_shm->remote_enable_succeeded[nr],
					   1, __ATOMIC_RELAXED);
		return;
	}

	if (nr < MAX_NR_SYSCALL)
		__atomic_fetch_add(&kcov_shm->remote_enable_failed[nr], 1,
				   __ATOMIC_RELAXED);

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
			kcov_latch_first_ebadf(kc, this_child());

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
	if (nr < MAX_NR_SYSCALL)
		__atomic_fetch_add(&kcov_shm->remote_fallback_to_local[nr], 1,
				   __ATOMIC_RELAXED);
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
				&kcov_shm->cmp_diag.runtime_disable_errno,
				&kcov_shm->cmp_diag.runtime_disable_count,
				errno);
		kc->cmp_enabled_this_call = false;
	}
}

void kcov_note_extrafork(struct kcov_child *kc, unsigned int nr)
{
	/* Denominator bump runs even when the child has no kcov (kc==NULL
	 * or !kc->active): per_syscall_extrafork_calls[] is a count of
	 * EXTRA_FORK dispatches through do_extrafork(), independent of
	 * whether the worker itself is a kcov producer.  kcov_shm is
	 * allocated by kcov_init_global() on every trinity startup, so
	 * the NULL guard is defensive against startup ordering / no-kcov
	 * builds only.  MAX_NR_SYSCALL upper-bound matches every other
	 * per_syscall_*[] writer in this file. */
	if (kcov_shm != NULL && nr < MAX_NR_SYSCALL)
		__atomic_fetch_add(&kcov_shm->per_syscall_extrafork_calls[nr],
				   1, __ATOMIC_RELAXED);

	if (kc == NULL || !kc->active)
		return;

	if (kc->mode == KCOV_MODE_PC) {
		if (kc->trace_buf != NULL)
			__atomic_store_n(&kc->trace_buf[0], 0,
					 __ATOMIC_RELAXED);
	} else if (kc->mode == KCOV_MODE_CMP) {
		if (kc->cmp_trace_buf != NULL)
			__atomic_store_n(&kc->cmp_trace_buf[0], 0,
					 __ATOMIC_RELAXED);
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
	kcov_collect(kc, (unsigned int)op_nr, false, &edges_this_call, NULL);
	kc->bracket_owned = false;
	return edges_this_call;
}

/*
 * Per-bracket record / insert tallies for the §3.2 anti-domination
 * caps.  File-scope statics, single-writer per child process
 * (trinity children are separate processes; each has its own copy),
 * reset to zero at every kcov_cmp_bracket_begin() and consulted by
 * childop_cmp_collect().  Not stashed on struct kcov_child to keep
 * its 48-byte hot-cacheline budget intact.
 */
static unsigned int childop_cmp_bracket_records_this;
static unsigned int childop_cmp_bracket_inserts_this;

/* KCOV CMP trace-buffer record format -- mirrors the constants in
 * cmp_hints.c so this file is self-contained and the harvest path
 * does not pull the cmp_hints.c hot-loop machinery into a wrapped
 * syscall's critical section. */
#define KCOV_CMP_REC_CONST		(1U << 0)
#define KCOV_CMP_REC_SIZE_SHIFT		1
#define KCOV_CMP_REC_SIZE_MASK		3U
#define KCOV_CMP_REC_WORDS		4

bool kcov_cmp_bracket_begin(struct kcov_child *kc)
{
	if (kc == NULL || !kc->active || kcov_shm == NULL) {
		/* kcov_shm == NULL also gates the bump itself so a defensive
		 * call before shm setup is a quiet no-op rather than a NULL
		 * deref.  Mirrors the PC-bracket gate. */
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->childop_cmp_brackets_skipped_inactive,
				1, __ATOMIC_RELAXED);
		return false;
	}
	if (kc->mode != KCOV_MODE_CMP) {
		__atomic_fetch_add(
			&kcov_shm->childop_cmp_brackets_skipped_pc_mode,
			1, __ATOMIC_RELAXED);
		return false;
	}
	if (!kc->cmp_capable || kc->cmp_trace_buf == NULL) {
		__atomic_fetch_add(
			&kcov_shm->childop_cmp_brackets_skipped_incapable,
			1, __ATOMIC_RELAXED);
		return false;
	}
	if (kc->bracket_owned) {
		__atomic_fetch_add(
			&kcov_shm->childop_cmp_brackets_skipped_nested,
			1, __ATOMIC_RELAXED);
		return false;
	}

	kcov_enable_cmp(kc);
	if (!kc->cmp_enabled_this_call) {
		/* kcov_enable_cmp gave up (runtime EBADF / unsupported);
		 * cmp_capable is now false.  Treat as the incapable reject
		 * arm so the attempts == opened + sum(skipped) invariant
		 * holds. */
		__atomic_fetch_add(
			&kcov_shm->childop_cmp_brackets_skipped_incapable,
			1, __ATOMIC_RELAXED);
		return false;
	}

	kc->bracket_owned = true;
	childop_cmp_bracket_records_this = 0;
	childop_cmp_bracket_inserts_this = 0;
	__atomic_fetch_add(&kcov_shm->childop_cmp_brackets_opened, 1,
			   __ATOMIC_RELAXED);
	return true;
}

void kcov_cmp_bracket_end(struct kcov_child *kc)
{
	if (kc == NULL || !kc->bracket_owned)
		return;
	/* kcov_disable already gates on kc->mode and cmp_enabled_this_call,
	 * so calling it on a CMP-mode child here issues exactly one
	 * KCOV_DISABLE on cmp_fd and clears cmp_enabled_this_call. */
	kcov_disable(kc);
	kc->bracket_owned = false;
}

void childop_cmp_reset(struct kcov_child *kc)
{
	if (kc == NULL || !kc->bracket_owned)
		return;
	if (kc->mode != KCOV_MODE_CMP || kc->cmp_trace_buf == NULL)
		return;
	/* Reset the count word so the wrapped syscall's CMP records start
	 * at slot 0 of cmp_trace_buf -- the kernel appends from the count
	 * the same way KCOV_ENABLE does at bracket entry. */
	__atomic_store_n(&kc->cmp_trace_buf[0], 0, __ATOMIC_RELAXED);
}

void childop_cmp_collect(struct kcov_child *kc, unsigned int nr)
{
	unsigned long count;
	unsigned long i;
	unsigned int kept = 0;
	unsigned int truncated = 0;
	unsigned long *trace_buf;

	if (kc == NULL || !kc->bracket_owned)
		return;
	if (kc->mode != KCOV_MODE_CMP || kc->cmp_trace_buf == NULL)
		return;
	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;

	trace_buf = kc->cmp_trace_buf;
	count = __atomic_load_n(&trace_buf[0], __ATOMIC_RELAXED);

	/* Clamp to KCOV_CMP_RECORDS_MAX and account the truncation
	 * against the per-nr trace_truncated counter -- mirrors the
	 * random-syscall path's cmp_trace_truncated row. */
	if (count >= KCOV_CMP_RECORDS_MAX) {
		count = KCOV_CMP_RECORDS_MAX;
		truncated = 1;
	}

	__atomic_fetch_add(&kcov_shm->childop_cmp_syscalls_sampled[nr], 1UL,
			   __ATOMIC_RELAXED);
	if (truncated)
		__atomic_fetch_add(&kcov_shm->childop_cmp_trace_truncated[nr],
				   1UL, __ATOMIC_RELAXED);

	if (count == 0)
		return;

	__atomic_fetch_add(&kcov_shm->childop_cmp_records_collected[nr],
			   count, __ATOMIC_RELAXED);

	for (i = 0; i < count; i++) {
		unsigned long *rec;
		unsigned long type, arg1, ip;
		unsigned int size;

		/* §3.2 anti-domination cap: drop further records on this
		 * bracket once the cap is hit so one chatty childop cannot
		 * dominate the lane (or burn cycles in this loop). */
		if (childop_cmp_bracket_records_this >=
		    CHILDOP_CMP_BRACKET_RECORDS_CAP) {
			__atomic_fetch_add(
				&kcov_shm->childop_cmp_record_cap_hits, 1UL,
				__ATOMIC_RELAXED);
			break;
		}
		childop_cmp_bracket_records_this++;

		rec = &trace_buf[1 + i * KCOV_CMP_REC_WORDS];
		type = rec[0];
		arg1 = rec[1];
		/* rec[2] is the runtime operand; feeding it back would
		 * recycle trinity's own inputs.  rec[3] is the comparison
		 * site PC. */
		ip   = kcov_canon_cmp_ip(rec[3]);
		size = 1U << ((type >> KCOV_CMP_REC_SIZE_SHIFT) &
			      KCOV_CMP_REC_SIZE_MASK);

		/* Only KCOV_CMP_CONST records expose a kernel-side
		 * compile-time constant; both-runtime records would just
		 * mirror values trinity already generated. */
		if (!(type & KCOV_CMP_REC_CONST))
			continue;

		/* Mirror cmp_hints_collect()'s boring-constant filter (the
		 * narrower ~3UL arm) so the quarantine lane is not flooded
		 * with 0/1/2/3 and (unsigned long)-1 sentinels.  The
		 * wider ~7UL arm is per-child A/B telemetry on the
		 * random-syscall path and is intentionally not replicated
		 * here -- this lane has no A/B yet. */
		if ((arg1 & ~3UL) == 0)
			continue;
		if (arg1 == (unsigned long)-1)
			continue;

		if (childop_cmp_bracket_inserts_this >=
		    CHILDOP_CMP_BRACKET_INSERTS_CAP) {
			__atomic_fetch_add(
				&kcov_shm->childop_cmp_insert_cap_hits, 1UL,
				__ATOMIC_RELAXED);
			break;
		}
		childop_cmp_bracket_inserts_this++;
		kept++;

		/* do32 = false: childops issue native 64-bit syscalls only. */
		cmp_hints_childop_insert(nr, false, ip, arg1, size);
	}

	if (kept > 0) {
		struct childdata *cc = this_child();

		if (cc != NULL) {
			unsigned int op = (unsigned int)cc->op_type;

			if (op < KCOV_CHILDOP_NR_MAX)
				__atomic_fetch_add(
				    &kcov_shm->childop_cmp_syscalls_sampled_per_op[op],
				    1UL, __ATOMIC_RELAXED);
		}
	}
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
 * KASLR-strip a kernel comparison-instruction address before it lands in
 * the cmp-hints bloom + per-syscall pool + persisted state file.  Same
 * transform as kcov_canon_pc -- both subtract the runtime _text base
 * resolved by kcov_get_kaslr_base -- but kept as a distinct entry point
 * for the cmp-hint side so cmp_hints.c has a single named ingress that
 * scripts/check-static/cmp-hints-canonicalise-cmp-ip.sh can enforce in
 * isolation from the PC-coverage canonicalisation rule.
 *
 * Without this, the cmp-hints pool indexed entries by the raw runtime
 * PC of the kernel comparison site; a KASLR reroll between save and
 * load shifted every cmp_ip by the difference in kernel-text bases, so
 * the kallsyms-fingerprint match said "same kernel" but the warm-loaded
 * pool aliased every constant to a different (cmp_ip, value, size) key.
 * Field-scoped scoring planned on top of cmp_ip would compound the
 * noise.  The persisted-file header now stamps kcov_kaslr_base alongside
 * the canonical cmp_ip values, and the load path rejects a canonical-vs-
 * raw mismatch the same way kcov_bitmap_file_header.kaslr_base does.
 */
unsigned long kcov_canon_cmp_ip(unsigned long ip)
{
	return ip - (unsigned long)kcov_kaslr_base;
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
 * Publish a new maximum probe distance to the shared counter.  The
 * probe==0 fast path (edge found on first probe) is the dominant case
 * and can never raise the max, so skip the shared-cacheline load there.
 */
static void kcov_note_max_probe(unsigned long probe)
{
	unsigned long cur;

	if (probe == 0)
		return;
	cur = __atomic_load_n(&kcov_shm->dedup_max_probe_seen,
		__ATOMIC_RELAXED);
	while (probe > cur) {
		if (__atomic_compare_exchange_n(&kcov_shm->dedup_max_probe_seen,
				&cur, probe,
				false,
				__ATOMIC_RELAXED,
				__ATOMIC_RELAXED))
			break;
	}
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
			kcov_note_max_probe(probe);
			s->generation = generation;
			s->edge_idx = edge;
			s->count = 1;
			return 1;
		}
		if (s->edge_idx == edge) {
			kcov_note_max_probe(probe);
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
		  unsigned long *new_edge_count,
		  struct kcov_pc_result *result)
{
	unsigned long count;
	unsigned long idx;
	unsigned long call_nr;
	unsigned long edges_this_call = 0;
	unsigned long distinct_edges_this_call = 0;
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
	if (result != NULL) {
		result->bucket_bits = 0;
		result->distinct_edges = 0;
		result->local_distinct_pcs = 0;
		result->transition_edges_real_local = 0;
		result->trace_size = 0;
	}

	if (!kc->active)
		return false;

	/* kcov_shm->total_calls is now bumped ONLY for its stamp role:
	 * the returned call_nr is stored into kcov_shm->last_edge_at[nr]
	 * on the found-new-edge branch below and read by the cold-skip
	 * gap denominator in kcov_syscall_cold_skip_pct() / by the
	 * last_efault_at[] stamp in syscall.c.  The dump-side accounting
	 * (post-mortem, stats.c JSON + Scuba rows, strategy snapshots)
	 * now reads parent_stats.total_calls instead, drained from the
	 * per-child kcov_child_local_stats staging counter bumped below. */
	call_nr = __atomic_fetch_add(&kcov_shm->total_calls,
		1, __ATOMIC_RELAXED);

	/* Per-child staging bumps for the dump-side total_calls /
	 * remote_calls accounting.  Lives on childdata->local_stats so
	 * the hot kcov_shm cacheline does not also take a relaxed
	 * atomic bump per call for the (formerly) duplicate dump
	 * accounting.  this_child() is NULL only in parent context,
	 * which kcov_collect()'s callers do not reach -- guard anyway
	 * so a future caller cannot crash the parent on a stray
	 * invocation.  kcov_shm->remote_calls is no longer bumped: no
	 * stamp-role consumer references the shm field, so the staged
	 * delta is the source of truth for the dump path. */
	{
		struct childdata *cc = this_child();

		if (cc != NULL && cc->local_stats != NULL) {
			cc->local_stats->total_calls++;
			if (kc->remote_mode)
				cc->local_stats->remote_calls++;
			cc->local_stats->local_syscalls_since_flush++;
		}
	}

	count = __atomic_load_n(&kc->trace_buf[0], __ATOMIC_RELAXED);
	if (count >= (unsigned long)kcov_trace_size - 1) {
		/* Kernel wanted to record more PCs than the buffer holds; the
		 * tail of this call's coverage was dropped.  Bump a counter so
		 * the post-mortem can show whether kcov_trace_size needs to
		 * grow again (raise it via --kcov-trace-size; the compile-time
		 * KCOV_TRACE_SIZE is just the default). */
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
		count = (unsigned long)kcov_trace_size - 1;
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
			if (old == 0) {
				__atomic_fetch_add(&kcov_shm->distinct_edges,
					1, __ATOMIC_RELAXED);
				distinct_edges_this_call++;
			}
		}

		prev_edge = edge;
		prev_bucket = bucket;
	}

	/* Per-child staging bump for the dump-side total_pcs.  Same
	 * batched-flush model as total_calls / remote_calls above; the
	 * delta here is +count (PCs returned by the kernel for this
	 * syscall), already a batched value at this site.  No
	 * stamp-role consumer reads kcov_shm->total_pcs, so the shm
	 * atomic is no longer bumped and the staged delta is the
	 * source of truth for the dump path. */
	{
		struct childdata *cc = this_child();

		if (cc != NULL && cc->local_stats != NULL)
			cc->local_stats->total_pcs += count;
	}

	if (nr < MAX_NR_SYSCALL) {
		__atomic_fetch_add(&kcov_shm->per_syscall_calls[nr],
			1, __ATOMIC_RELAXED);
		/* per-syscall split of
		 * kcov_collect() activity by collection mode.  See the field
		 * comments in include/kcov.h: a remote-sampled syscall lands
		 * in KCOV_MODE_REMOTE and drops synchronous local PC, so a
		 * static remote sampling policy can spend half a syscall's
		 * samples on a mode with no annotated producer.  Bump every
		 * call into the mode-keyed slot so per-mode yield is
		 * measurable per syscall. */
		if (kc->remote_mode)
			__atomic_fetch_add(&kcov_shm->remote_pc_calls[nr],
				1, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->local_pc_calls[nr],
				1, __ATOMIC_RELAXED);
		if (found_new) {
			/* Mirror the per_syscall_edges call-count + raw-edge
			 * split above into the local/remote slots so the
			 * mode-keyed yield ratio (edge_calls / pc_calls and
			 * edge_count / pc_calls) is directly readable. */
			if (kc->remote_mode) {
				__atomic_fetch_add(
					&kcov_shm->remote_pc_edge_calls[nr],
					1, __ATOMIC_RELAXED);
				__atomic_fetch_add(
					&kcov_shm->remote_pc_edge_count[nr],
					edges_this_call, __ATOMIC_RELAXED);
			} else {
				__atomic_fetch_add(
					&kcov_shm->local_pc_edge_calls[nr],
					1, __ATOMIC_RELAXED);
				__atomic_fetch_add(
					&kcov_shm->local_pc_edge_count[nr],
					edges_this_call, __ATOMIC_RELAXED);
			}
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
			/* Per-child staging bump for the dump-side run-wide
			 * warm-known-hits counter.  Same batched-flush model
			 * as total_calls / remote_calls / total_pcs above;
			 * no stamp-role consumer reads
			 * kcov_shm->total_warm_known_hits, so the shm atomic
			 * is no longer bumped and the staged delta is the
			 * source of truth for the dump path.  The per-syscall
			 * split above stays on the shm atomic -- it's an nr-
			 * indexed array, not the cross-child cacheline-bounce
			 * scalar this migration targets. */
			{
				struct childdata *cc = this_child();

				if (cc != NULL && cc->local_stats != NULL)
					cc->local_stats->total_warm_known_hits++;
			}
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
		 * single slot.
		 *
		 * per_syscall_transition_edges_real_local mirrors the _real
		 * counter restricted to local-mode kcov traces (remote-mode
		 * traces merge coverage copied from remote contexts whose PC
		 * ordering is not verified to preserve transition adjacency
		 * -- see the kcov_transition_reward_mode enum comment in
		 * include/kcov.h).  It is the local-only signal frontier_
		 * cold_weight() folds into its blend; the unfiltered _real
		 * counter stays the stats-dump observability signal so the
		 * top-N output keeps reflecting the full transition load.
		 * Gated additionally on kcov_transition_reward_mode != OFF
		 * so OFF mode pays zero per-call cost. */
		if (transitions_this_call > 0) {
			enum kcov_transition_reward_mode trew_mode =
				__atomic_load_n(&kcov_transition_reward_mode,
						__ATOMIC_RELAXED);

			__atomic_fetch_add(
				&kcov_shm->per_syscall_transition_edges[nr],
				1, __ATOMIC_RELAXED);
			__atomic_fetch_add(
				&kcov_shm->per_syscall_transition_edges_real[nr],
				transitions_this_call, __ATOMIC_RELAXED);
			if (!kc->remote_mode &&
			    trew_mode != KCOV_TRANSITION_REWARD_OFF)
				__atomic_fetch_add(
					&kcov_shm->per_syscall_transition_edges_real_local[nr],
					transitions_this_call,
					__ATOMIC_RELAXED);

			/* SHADOW-ONLY topology-pair sample, transition lane.
			 * Co-located with the
			 * unconditional per_syscall_transition_edges_real bump
			 * above so the topology aggregate's transition lane
			 * fires whenever a transition is discovered, regardless
			 * of the kcov_transition_reward_mode rollback knob or
			 * the local/remote split downstream gates apply.  The
			 * PC-edge sibling tail call in frontier_record_new_edge
			 * (below the found_new branch above) is similarly
			 * unconditional on mode -- this co-location keeps the
			 * PC and transition lanes drawing from the same child
			 * population for the per-setup_op comparison the shadow
			 * aggregator surfaces. */
			topo_pair_record_shadow(nr,
						TOPO_PAIR_REASON_TRANSITION);
		}
	} else if (nr >= CHILDOP_KCOV_NR_BASE) {
		/* per-childop mirror
		 * of the per-syscall local/remote PC split above.  Indexed
		 * by op = nr - CHILDOP_KCOV_NR_BASE; bounds-clamped against
		 * KCOV_CHILDOP_NR_MAX (the in-tree _Static_assert pins
		 * NR_CHILD_OP_TYPES below the bound, but the guard stays
		 * paranoid since nr is composed from a child_op_type value
		 * outside this file). */
		unsigned long op = nr - CHILDOP_KCOV_NR_BASE;

		if (op < KCOV_CHILDOP_NR_MAX) {
			if (kc->remote_mode)
				__atomic_fetch_add(
					&kcov_shm->childop_remote_pc_calls[op],
					1, __ATOMIC_RELAXED);
			else
				__atomic_fetch_add(
					&kcov_shm->childop_local_pc_calls[op],
					1, __ATOMIC_RELAXED);
			if (found_new) {
				if (kc->remote_mode) {
					__atomic_fetch_add(
						&kcov_shm->childop_remote_pc_edge_calls[op],
						1, __ATOMIC_RELAXED);
					__atomic_fetch_add(
						&kcov_shm->childop_remote_pc_edge_count[op],
						edges_this_call, __ATOMIC_RELAXED);
				} else {
					__atomic_fetch_add(
						&kcov_shm->childop_local_pc_edge_calls[op],
						1, __ATOMIC_RELAXED);
					__atomic_fetch_add(
						&kcov_shm->childop_local_pc_edge_count[op],
						edges_this_call, __ATOMIC_RELAXED);
				}
			}
		}
	}

	if (new_edge_count != NULL)
		*new_edge_count = edges_this_call;
	if (result != NULL) {
		result->bucket_bits = edges_this_call;
		result->distinct_edges = distinct_edges_this_call;
		result->local_distinct_pcs = local_distinct_pcs;
		/* Post-cap PC count from the trace header above (already
		 * clamped to kcov_trace_size - 1 when the buffer filled),
		 * surfaced so post-collect callers can recognise calls whose
		 * trace approached the buffer ceiling without re-reading
		 * trace_buf[0].  Same value the trace_truncated /
		 * max_trace_size accounting consumed; this is a single store
		 * with no new load. */
		result->trace_size = count;
		/* Zeroed for remote-mode traces (the live-reward path
		 * excludes them -- see the kcov_transition_reward_mode
		 * remote-mode contract in include/kcov.h) and for OFF mode
		 * (which never ran the inner tcov bump branch but the
		 * per-call counter would still be a valid local count;
		 * gating here keeps the caller-side accounting symmetric
		 * with the per_syscall_transition_edges_real_local gate
		 * above so OFF mode pays zero attribution cost). */
		if (!kc->remote_mode &&
		    __atomic_load_n(&kcov_transition_reward_mode,
				    __ATOMIC_RELAXED) !=
		    KCOV_TRANSITION_REWARD_OFF)
			result->transition_edges_real_local =
				transitions_this_call;
	}

	/* Drain the per-child kcov_child_local_stats staging counters
	 * into parent_stats via the stats_ring on either trigger:
	 *   (a) found_new -- a fresh edge already costs a dump-side
	 *       notification, fold the staged delta into the same drain;
	 *   (b) the syscalls-since-flush counter has reached the cadence
	 *       cap, so a long run of no-new-edge calls still publishes.
	 * The bumps above are gated on this_child() != NULL && local_stats
	 * != NULL; mirror that gate here. */
	{
		struct childdata *cc = this_child();

		if (cc != NULL && cc->local_stats != NULL) {
			if (found_new ||
			    cc->local_stats->local_syscalls_since_flush >=
				    KCOV_LOCAL_STATS_FLUSH_SYSCALLS)
				kcov_child_flush_stats(cc);
		}
	}

	/* Diagnostic coverage-jump breadcrumb -- pure observability, no
	 * behaviour gate.  See kcov_covjump_breadcrumb_maybe() for the
	 * contract; call_nr is the kcov_shm->total_calls stamp this
	 * call took at the top of kcov_collect(). */
	kcov_covjump_breadcrumb_maybe(call_nr);

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

/*
 * Coverage-jump breadcrumb -- diagnostic only.
 *
 * Sampled at the tail of kcov_collect() so call_nr (the kcov_shm->
 * total_calls fetch_add return from earlier in this call) is in hand
 * without a second atomic read.  See the KCOV_COVJUMP_* block in
 * include/kcov.h for the detector contract.
 *
 * No runtime behaviour reads any output of this path: it writes one
 * stats.log line when the (distinct_edges) coverage delta over a
 * KCOV_COVJUMP_WINDOW_CALLS-sized window crosses KCOV_COVJUMP_DELTA_
 * THRESHOLD, rate-capped to one line per KCOV_COVJUMP_RATE_CAP_CALLS
 * total_calls.  All emitted facts (recent syscalls, top childop
 * deltas, plateau hypothesis + bandit arm name, corpus save/replay
 * deltas) are observability snapshots taken by the CAS winner -- no
 * fleet counter is written, no policy is consulted.
 *
 * The CAS on covjump_window_start_call_nr serialises window advances
 * across racing children so only one breadcrumb fires per window even
 * when many children cross the boundary in the same instant.
 */
static const enum child_op_type covjump_bridge_ops[] = {
	CHILD_OP_BRIDGE_FDB_STP,
	CHILD_OP_BRIDGE_VLAN_CHURN,
	CHILD_OP_BRIDGE_CT_CHURN,
};
static const enum child_op_type covjump_conntrack_ops[] = {
	CHILD_OP_NF_CONNTRACK_HELPER,
};
static const enum child_op_type covjump_mld_ops[] = {
	CHILD_OP_IGMP_MLD_SOURCE_CHURN,
};
static const enum child_op_type covjump_mempress_ops[] = {
	CHILD_OP_MEMORY_PRESSURE,
	CHILD_OP_MLOCK_PRESSURE,
};

static bool covjump_any_delta(const enum child_op_type *ops, unsigned int n,
			      const unsigned long *now,
			      const unsigned long *snap)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		unsigned int op = (unsigned int)ops[i];

		if (op >= KCOV_CHILDOP_NR_MAX)
			continue;
		if (now[op] > snap[op])
			return true;
	}
	return false;
}

static void covjump_seed_snapshot(unsigned long call_nr, unsigned long edges_now)
{
	unsigned int op;

	__atomic_store_n(&kcov_shm->covjump_window_start_call_nr, call_nr,
			 __ATOMIC_RELAXED);
	__atomic_store_n(&kcov_shm->covjump_window_start_distinct_edges,
			 edges_now, __ATOMIC_RELAXED);
	if (minicorpus_shm != NULL) {
		__atomic_store_n(&kcov_shm->covjump_snap_saves_pc,
			__atomic_load_n(&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_PC],
					__ATOMIC_RELAXED),
			__ATOMIC_RELAXED);
		__atomic_store_n(&kcov_shm->covjump_snap_saves_cmp,
			__atomic_load_n(&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_CMP],
					__ATOMIC_RELAXED),
			__ATOMIC_RELAXED);
	}
	if (chain_corpus_shm != NULL) {
		__atomic_store_n(&kcov_shm->covjump_snap_chain_saves,
			__atomic_load_n(&chain_corpus_shm->save_count,
					__ATOMIC_RELAXED),
			__ATOMIC_RELAXED);
		__atomic_store_n(&kcov_shm->covjump_snap_chain_replays,
			__atomic_load_n(&chain_corpus_shm->replay_count,
					__ATOMIC_RELAXED),
			__ATOMIC_RELAXED);
	}
	for (op = 0; op < KCOV_CHILDOP_NR_MAX; op++) {
		unsigned long v = 0;

		if (op < (unsigned int)NR_CHILD_OP_TYPES)
			v = __atomic_load_n(&shm->stats.childop_invocations[op],
					    __ATOMIC_RELAXED);
		__atomic_store_n(&kcov_shm->covjump_snap_childop_invocations[op],
				 v, __ATOMIC_RELAXED);
	}
}

static void kcov_covjump_breadcrumb_maybe(unsigned long call_nr)
{
	unsigned long expected_start, edges_now, edges_prev, delta;
	unsigned long elapsed, last_emit, sample_calls;
	unsigned long now_childop[KCOV_CHILDOP_NR_MAX];
	unsigned long snap_childop[KCOV_CHILDOP_NR_MAX];
	unsigned long saves_pc_now = 0, saves_cmp_now = 0;
	unsigned long chain_saves_now = 0, chain_replays_now = 0;
	unsigned long saves_pc_snap, saves_cmp_snap;
	unsigned long chain_saves_snap, chain_replays_snap;
	unsigned int top_idx[KCOV_COVJUMP_RECENT_N];
	unsigned long top_delta[KCOV_COVJUMP_RECENT_N];
	char syscalls_buf[256];
	char childops_buf[256];
	char tag_buf[64];
	unsigned int top_n = 0;
	unsigned int op, i;
	struct childdata *cc;
	enum plateau_hypothesis hyp;
	int arm;
	bool bridge_hit, conntrack_hit, mld_hit, mempress_hit;

	if (kcov_shm == NULL)
		return;

	/* First-call arm.  RELEASE-store the gate after the companion
	 * fields are seeded so a peer that observes covjump_window_armed
	 * via the ACQUIRE pair below also sees the freshly seeded
	 * snapshot. */
	if (!__atomic_load_n(&kcov_shm->covjump_window_armed,
			     __ATOMIC_ACQUIRE)) {
		bool expected = false;

		edges_now = __atomic_load_n(&kcov_shm->distinct_edges,
					    __ATOMIC_RELAXED);
		covjump_seed_snapshot(call_nr, edges_now);
		__atomic_compare_exchange_n(&kcov_shm->covjump_window_armed,
			&expected, true, false,
			__ATOMIC_RELEASE, __ATOMIC_RELAXED);
		return;
	}

	expected_start = __atomic_load_n(&kcov_shm->covjump_window_start_call_nr,
					 __ATOMIC_RELAXED);
	if (call_nr <= expected_start)
		return;
	elapsed = call_nr - expected_start;
	if (elapsed < KCOV_COVJUMP_WINDOW_CALLS)
		return;

	/* CAS-elect a single window-advance winner.  Losers see the new
	 * start on a later call and re-evaluate. */
	if (!__atomic_compare_exchange_n(&kcov_shm->covjump_window_start_call_nr,
		&expected_start, call_nr, false,
		__ATOMIC_RELAXED, __ATOMIC_RELAXED))
		return;

	sample_calls = call_nr - expected_start;
	edges_now = __atomic_load_n(&kcov_shm->distinct_edges, __ATOMIC_RELAXED);
	edges_prev = __atomic_load_n(&kcov_shm->covjump_window_start_distinct_edges,
				     __ATOMIC_RELAXED);
	delta = (edges_now >= edges_prev) ? edges_now - edges_prev : 0;

	/* Refresh the edge snapshot every window even when the delta is
	 * sub-threshold so the NEXT window measures a contiguous interval. */
	__atomic_store_n(&kcov_shm->covjump_window_start_distinct_edges,
			 edges_now, __ATOMIC_RELAXED);

	if (delta < KCOV_COVJUMP_DELTA_THRESHOLD)
		goto refresh_snapshot;

	last_emit = __atomic_load_n(&kcov_shm->covjump_last_emit_call_nr,
				    __ATOMIC_RELAXED);
	if (last_emit != 0 && call_nr - last_emit < KCOV_COVJUMP_RATE_CAP_CALLS)
		goto refresh_snapshot;
	__atomic_store_n(&kcov_shm->covjump_last_emit_call_nr, call_nr,
			 __ATOMIC_RELAXED);

	/* Snapshot live + saved counters for the line. */
	if (minicorpus_shm != NULL) {
		saves_pc_now = __atomic_load_n(&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_PC],
					       __ATOMIC_RELAXED);
		saves_cmp_now = __atomic_load_n(&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_CMP],
						__ATOMIC_RELAXED);
	}
	if (chain_corpus_shm != NULL) {
		chain_saves_now = __atomic_load_n(&chain_corpus_shm->save_count,
						  __ATOMIC_RELAXED);
		chain_replays_now = __atomic_load_n(&chain_corpus_shm->replay_count,
						    __ATOMIC_RELAXED);
	}
	saves_pc_snap = __atomic_load_n(&kcov_shm->covjump_snap_saves_pc,
					__ATOMIC_RELAXED);
	saves_cmp_snap = __atomic_load_n(&kcov_shm->covjump_snap_saves_cmp,
					 __ATOMIC_RELAXED);
	chain_saves_snap = __atomic_load_n(&kcov_shm->covjump_snap_chain_saves,
					   __ATOMIC_RELAXED);
	chain_replays_snap = __atomic_load_n(&kcov_shm->covjump_snap_chain_replays,
					     __ATOMIC_RELAXED);
	for (op = 0; op < KCOV_CHILDOP_NR_MAX; op++) {
		now_childop[op] = 0;
		if (op < (unsigned int)NR_CHILD_OP_TYPES)
			now_childop[op] = __atomic_load_n(
				&shm->stats.childop_invocations[op],
				__ATOMIC_RELAXED);
		snap_childop[op] = __atomic_load_n(
			&kcov_shm->covjump_snap_childop_invocations[op],
			__ATOMIC_RELAXED);
	}

	/* Top-N childops by per-window invocation delta.  Trivial
	 * insertion sort over the small KCOV_COVJUMP_RECENT_N tail. */
	for (i = 0; i < KCOV_COVJUMP_RECENT_N; i++) {
		top_idx[i] = 0;
		top_delta[i] = 0;
	}
	for (op = 0; op < KCOV_CHILDOP_NR_MAX && op < (unsigned int)NR_CHILD_OP_TYPES; op++) {
		unsigned long d;

		if (now_childop[op] <= snap_childop[op])
			continue;
		d = now_childop[op] - snap_childop[op];
		for (i = 0; i < KCOV_COVJUMP_RECENT_N; i++) {
			if (d > top_delta[i]) {
				unsigned int j;

				for (j = KCOV_COVJUMP_RECENT_N - 1; j > i; j--) {
					top_delta[j] = top_delta[j - 1];
					top_idx[j] = top_idx[j - 1];
				}
				top_delta[i] = d;
				top_idx[i] = op;
				if (top_n < KCOV_COVJUMP_RECENT_N)
					top_n++;
				break;
			}
		}
	}

	bridge_hit = covjump_any_delta(covjump_bridge_ops,
		sizeof(covjump_bridge_ops) / sizeof(covjump_bridge_ops[0]),
		now_childop, snap_childop);
	conntrack_hit = covjump_any_delta(covjump_conntrack_ops,
		sizeof(covjump_conntrack_ops) / sizeof(covjump_conntrack_ops[0]),
		now_childop, snap_childop);
	mld_hit = covjump_any_delta(covjump_mld_ops,
		sizeof(covjump_mld_ops) / sizeof(covjump_mld_ops[0]),
		now_childop, snap_childop);
	mempress_hit = covjump_any_delta(covjump_mempress_ops,
		sizeof(covjump_mempress_ops) / sizeof(covjump_mempress_ops[0]),
		now_childop, snap_childop);

	/* Recent per-child syscall names from THIS child's syscall_ring
	 * (the CAS winner -- one of many in-flight children).  Bounded to
	 * KCOV_COVJUMP_RECENT_N entries; head-1 is the most recent. */
	syscalls_buf[0] = '\0';
	cc = this_child();
	if (cc != NULL) {
		struct child_syscall_ring *ring = &cc->syscall_ring;
		uint32_t head = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);
		size_t pos = 0;

		for (i = 0; i < KCOV_COVJUMP_RECENT_N; i++) {
			uint32_t slot;
			const struct chronicle_slot *s;
			const char *name;
			int n;

			if (head == 0 && i == 0)
				break;
			slot = (head + CHILD_SYSCALL_RING_SIZE - 1 - i)
				% CHILD_SYSCALL_RING_SIZE;
			s = &ring->recent[slot];
			if (!s->valid)
				break;
			name = print_syscall_name(s->nr, s->do32bit);
			if (name == NULL)
				name = "?";
			n = snprintf(syscalls_buf + pos,
				     sizeof(syscalls_buf) - pos,
				     "%s%s", pos == 0 ? "" : ",", name);
			if (n < 0 || (size_t)n >= sizeof(syscalls_buf) - pos)
				break;
			pos += (size_t)n;
		}
	}
	if (syscalls_buf[0] == '\0')
		snprintf(syscalls_buf, sizeof(syscalls_buf), "none");

	childops_buf[0] = '\0';
	{
		size_t pos = 0;

		for (i = 0; i < top_n; i++) {
			const char *name = alt_op_name(
				(enum child_op_type)top_idx[i]);
			int n;

			if (name == NULL)
				name = "?";
			n = snprintf(childops_buf + pos,
				     sizeof(childops_buf) - pos,
				     "%s%s:%lu", pos == 0 ? "" : ",",
				     name, top_delta[i]);
			if (n < 0 || (size_t)n >= sizeof(childops_buf) - pos)
				break;
			pos += (size_t)n;
		}
	}
	if (childops_buf[0] == '\0')
		snprintf(childops_buf, sizeof(childops_buf), "none");

	hyp = strategy_plateau_hypothesis_current();
	arm = __atomic_load_n(&shm->current_strategy, __ATOMIC_RELAXED);
	tag_buf[0] = '\0';
	{
		size_t pos = 0;
		int n;

		if (bridge_hit) {
			n = snprintf(tag_buf + pos, sizeof(tag_buf) - pos,
				     "bridge");
			if (n > 0) pos += (size_t)n;
		}
		if (conntrack_hit && pos < sizeof(tag_buf)) {
			n = snprintf(tag_buf + pos, sizeof(tag_buf) - pos,
				     "%sconntrack", pos == 0 ? "" : ",");
			if (n > 0) pos += (size_t)n;
		}
		if (mld_hit && pos < sizeof(tag_buf)) {
			n = snprintf(tag_buf + pos, sizeof(tag_buf) - pos,
				     "%smld", pos == 0 ? "" : ",");
			if (n > 0) pos += (size_t)n;
		}
		if (mempress_hit && pos < sizeof(tag_buf)) {
			/* Last tag in the chain -- no further appends, so we
			 * neither capture snprintf's return nor advance pos. */
			(void) snprintf(tag_buf + pos, sizeof(tag_buf) - pos,
					"%smempress", pos == 0 ? "" : ",");
		}
	}
	if (tag_buf[0] == '\0')
		snprintf(tag_buf, sizeof(tag_buf), "none");

	stats_log_write(
		"COVJUMP: distinct_edges +%lu over %lu calls (>=%lu) prev=%lu now=%lu hypothesis=%s arm=%s syscalls=[%s] childops=[%s] saves(pc/cmp)=+%lu/+%lu chain(save/replay)=+%lu/+%lu tags=[%s]\n",
		delta, sample_calls, KCOV_COVJUMP_DELTA_THRESHOLD,
		edges_prev, edges_now,
		strategy_plateau_hypothesis_name(hyp),
		strategy_name(arm),
		syscalls_buf, childops_buf,
		saves_pc_now > saves_pc_snap ? saves_pc_now - saves_pc_snap : 0UL,
		saves_cmp_now > saves_cmp_snap ? saves_cmp_now - saves_cmp_snap : 0UL,
		chain_saves_now > chain_saves_snap ? chain_saves_now - chain_saves_snap : 0UL,
		chain_replays_now > chain_replays_snap ? chain_replays_now - chain_replays_snap : 0UL,
		tag_buf);

refresh_snapshot:
	covjump_seed_snapshot(call_nr, edges_now);
}

void kcov_plateau_check(void)
{
	unsigned long edges_now, delta;
	struct timespec ts;
	time_t now;
	long elapsed;

	if (kcov_shm == NULL)
		return;

	/* CLOCK_MONOTONIC: window math must not be perturbed by a backward
	 * wall-clock step (e.g. an NTP correction), which under the prior
	 * CLOCK_REALTIME sampling yielded a negative elapsed and bogus
	 * plateau-window arithmetic.  plateau_window_start and
	 * plateau_entered_at are stamped from the monotonic clock too, so
	 * before/after stay in the same domain. */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec;
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

	elapsed = (long)(now - __atomic_load_n(&kcov_shm->plateau_window_start,
					       __ATOMIC_RELAXED));
	if (elapsed < 0)
		elapsed = 0;
	if (elapsed < KCOV_PLATEAU_WINDOW_SEC)
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
		long elapsed_secs = (long)(now - __atomic_load_n(
				&kcov_shm->plateau_entered_at,
				__ATOMIC_RELAXED));
		long minutes = elapsed_secs > 0 ? elapsed_secs / 60 : 0;

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

