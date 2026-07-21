/*
 * KCOV fd lifetime and per-child setup: KASLR-base lookup that turns
 * runtime PCs into build-invariant edge indices, the kcov_init_global
 * bootstrap, all four kcov_init_child_* helpers and their
 * kcov_init_child coordinator, kcov_child_flush_stats,
 * kcov_cleanup_child, and the kcov_recover_fd EBADF re-open path.
 * Carved out of kcov.c so every fd-lifetime invariant lives in one
 * translation unit; the enable / disable arms in kcov/enable.c reach
 * kcov_recover_fd via the extern in kcov-internal.h.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "fd.h"
#include "kcov-internal.h"
#include "params.h"		/* kcov_trace_size */
#include "pids.h"
#include "shm.h"
#include "stats_ring.h"		/* stats_ring_enqueue, STATS_FIELD_* */
#include "trinity.h"		/* output, outputerr */

#include "kernel/fcntl.h"
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
 * Parking KCOV at 60000 keeps it clear of any plausible picker
 * fd range -- fuzzer-pickers that allocate fds densely
 * (epoll/eventfd churn, slab-cache-thrash op, etc.) cannot land
 * siblings in the same numeric range as KCOV's relocated slots
 * -- and is defence-in-depth against a stale-close race
 * producing the EBADF cascade.  If the dup fails for any reason
 * the original low fd is kept and the registry catches
 * subsequent attempts on it.
 */
#define KCOV_FD_HIGH_BASE 60000U

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
		kcov_shm->coverage.distinct_edges, kcov_shm->coverage.edges_found);
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
 * Second KCOV fd dedicated to KCOV_TRACE_CMP.  Each child runs
 * in a single fixed mode for its lifetime -- KCOV_MODE_PC or
 * KCOV_MODE_CMP, picked once below from the cmp_capable +
 * random-draw block -- so the cmp fd is only actually enabled
 * for CMP-mode children.  Per-child mode selection keeps each
 * child's collection loop simple and avoids interleaving PC and
 * CMP reads on the same fd.  Probe
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
		__atomic_fetch_add(&kcov_shm->child_mode.cmp_mode_children, 1,
			__ATOMIC_RELAXED);
	else
		__atomic_fetch_add(&kcov_shm->child_mode.pc_mode_children, 1,
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
 * pre-existing kcov_shm->coverage.total_calls atomic was a relaxed bump
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
bool kcov_recover_fd(struct kcov_child *kc, bool is_cmp)
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
