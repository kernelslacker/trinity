/*
 * KCOV diagnostic surfaces: per-site failure formatters (kcov_pc_diag_
 * format, kcov_cmp_diag_format) that the periodic stats dump splices
 * into its output, and the one-shot EBADF chronicle latch
 * (kcov_first_ebadf_trap_drain, kcov_latch_first_ebadf) that captures
 * the in-flight context the first time any child observes EBADF on a
 * PC-enable ioctl.  Carved out of kcov.c so the diagnostic surface
 * has a single home; the enable / lifecycle clusters call
 * kcov_diag_record and kcov_latch_first_ebadf from their error arms
 * via the extern decls in kcov-internal.h.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "child.h"		/* struct childdata, chronicle_slot */
#include "fd.h"			/* fd_is_protected, lowest_protected_fd_in_range */
#include "kcov-internal.h"	/* kcov_shm, kcov_diag_record, kcov_latch_first_ebadf */
#include "pids.h"		/* this_child */
#include "shm.h"		/* shm */
#include "syscall.h"		/* struct syscallentry */
#include "tables.h"		/* get_syscall_entry */
#include "trinity.h"		/* output */

#include "kernel/fcntl.h"
/* F_DUPFD_QUERY may be missing on glibcs that predate it; replicate
 * the include/kernel fallback headers definition locally so the EBADF chronicle-slot
 * classifier can match the cmd without pulling unnecessary headers (which double-
 * defines struct file_attr against linux/fs.h that struct_catalog.h
 * already pulls into this TU via minicorpus.h). */
#ifndef F_DUPFD_QUERY
#define F_DUPFD_QUERY (1024 + 3)
#endif

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
void kcov_diag_record(int *errno_slot, unsigned int *count_slot,
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
 * loop summary (main/loop.c) walked the same six fields with copy-pasted
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
	/* ACQUIRE pairs with the RELEASE publish in kcov_latch_first_ebadf():
	 * if valid=1 is visible, every payload store below is too.  Load
	 * first_ebadf_op_nr only after the beacon so the winner value is
	 * from the same latched snapshot. */
	if (__atomic_load_n(&d->first_ebadf_valid, __ATOMIC_ACQUIRE))
		first_op_nr = __atomic_load_n(&d->first_ebadf_op_nr, __ATOMIC_RELAXED);
	else
		first_op_nr = 0;

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

			if (fd_count > KCOV_FIRST_EBADF_PROC_FD_MAX)
				fd_count = KCOV_FIRST_EBADF_PROC_FD_MAX;

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
	/* ACQUIRE pairs with the RELEASE publish in kcov_latch_first_ebadf():
	 * without it the CAS-elected op_nr can be visible before the payload
	 * stores below settle, and the trap dump prints stale zero fields. */
	if (!__atomic_load_n(&d->first_ebadf_valid, __ATOMIC_ACQUIRE))
		return false;
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
 * One-shot snapshot of the in-flight context the first time any child
 * observes EBADF from a PC-enable ioctl.  CAS-from-zero on
 * first_ebadf_op_nr is the gate -- subsequent failures (from this
 * caller OR the remote-fallback caller) see a non-zero slot and skip
 * the stores below, so the captured fields stay consistent w.r.t.
 * each other and the latch fires at most once across both PC-enable
 * arms.  op_nr + 1 offsets the empty-slot sentinel (0) from the
 * legitimate "EBADF on the very first syscall" reading.
 */
void kcov_latch_first_ebadf(struct kcov_child *kc, struct childdata *c)
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
		 * the latch -- the payload beacon
		 * first_ebadf_valid below carries the
		 * inter-thread ordering). */
		__atomic_store_n(
			&kcov_shm->pc_diag.first_ebadf_proc_fd_count,
			(unsigned char) snap_count,
			__ATOMIC_RELAXED);
		/* Payload publish beacon.  RELEASE pairs with the
		 * ACQUIRE load in kcov_diag_record() and
		 * kcov_first_ebadf_trap_drain(): a reader that
		 * observes valid=1 is guaranteed to see every
		 * relaxed payload store above.  Without this the
		 * CAS on first_ebadf_op_nr publishes the winner
		 * mark BEFORE the payload stores, so a naive
		 * reader could latch a non-zero op_nr and then
		 * copy out stale zeroed payload fields. */
		__atomic_store_n(
			&kcov_shm->pc_diag.first_ebadf_valid,
			1, __ATOMIC_RELEASE);
	}
}
