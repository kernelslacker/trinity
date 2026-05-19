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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cmp_hints.h"
#include "edgepair.h"
#include "healer.h"
#include "kcov.h"
#include "params.h"
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "trinity.h"
#include "utils.h"

/* KCOV ioctl commands (from linux/kcov.h). */
#define KCOV_INIT_TRACE    _IOR('c', 1, unsigned long)
#define KCOV_ENABLE        _IO('c', 100)
#define KCOV_DISABLE       _IO('c', 101)
#define KCOV_REMOTE_ENABLE _IOW('c', 102, struct kcov_remote_arg)

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

/*
 * Record a KCOV_TRACE_CMP setup/runtime failure into the parent-visible
 * cmp_diag slots.  Called from child context (post-dup2-to-/dev/null),
 * where output() to stdout is silently dropped — the shm fields are
 * the only diagnostic channel that survives back to the parent.
 *
 * First failure wins for the errno slot: CAS-from-zero so subsequent
 * failures at the same site don't overwrite the original errno.  The
 * count slot atomically tallies every failure so the parent can see
 * how many children hit each site even when they all hit the same one.
 */
static void kcov_cmp_diag_record(int *errno_slot, unsigned int *count_slot,
				 int err)
{
	int expected = 0;
	__atomic_compare_exchange_n(errno_slot, &expected, err, false,
		__ATOMIC_RELAXED, __ATOMIC_RELAXED);
	__atomic_fetch_add(count_slot, 1, __ATOMIC_RELAXED);
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
	kcov_shm = alloc_shared(sizeof(struct kcov_shared));
	memset(kcov_shm, 0, sizeof(struct kcov_shared));
	output(0, "KCOV: coverage collection enabled (%lu MB bucket-seen table, %u edges, %u buckets)\n",
		(unsigned long)KCOV_NUM_EDGES / (1024 * 1024),
		KCOV_NUM_EDGES, KCOV_NUM_BUCKETS);

	edgepair_init_global();
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
	kc->dedup = NULL;
	kc->current_generation = 0;

	if (kcov_shm == NULL)
		return;

	/*
	 * Per-child, child-private dedup table for hit-count bucketing.
	 * calloc() so post-fork children get their own copy under COW with
	 * every slot's generation field starting at 0.  The first
	 * kcov_collect() bumps current_generation to 1, so all slots
	 * immediately look stale and the table behaves as if just wiped —
	 * without paying the per-call memset cost.
	 */
	kc->dedup = calloc(KCOV_DEDUP_SIZE, sizeof(*kc->dedup));
	if (kc->dedup == NULL)
		return;

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

	/* Probe for KCOV_REMOTE_ENABLE support.  Try a remote enable/disable
	 * cycle — if the ioctl succeeds, the kernel supports it. */
	{
		struct kcov_remote_arg *arg;

		arg = calloc(1, sizeof(*arg));
		if (arg != NULL) {
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
	}

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
	 * Second KCOV fd dedicated to KCOV_TRACE_CMP.  Trinity used to
	 * mode-toggle the single PC fd into CMP for 1-in-CMP_MODE_RATIO
	 * syscalls, which traded a sliver of every-syscall PC coverage for
	 * occasional comparison-operand hints.  With a dedicated fd we run
	 * both modes simultaneously on every syscall — PC coverage is no
	 * longer sacrificed, and CMP records accumulate at the maximum
	 * possible rate.  Probe enable/disable here so a kernel without
	 * KCOV_TRACE_CMP support degrades cleanly to PC-only without
	 * disabling the rest of KCOV.  Per-child cost: one extra fd plus
	 * KCOV_CMP_BUFFER_SIZE * sizeof(unsigned long) (~2MB) of mmap.
	 */
	if (kc->active) {
		kc->cmp_fd = open("/sys/kernel/debug/kcov", O_RDWR);
		if (kc->cmp_fd < 0) {
			kcov_cmp_diag_record(&kcov_shm->cmp_diag.init_open_errno,
				&kcov_shm->cmp_diag.init_open_count, errno);
		} else {
			if (ioctl(kc->cmp_fd, KCOV_INIT_TRACE,
					(unsigned long)KCOV_CMP_BUFFER_SIZE) < 0) {
				kcov_cmp_diag_record(&kcov_shm->cmp_diag.init_init_trace_errno,
					&kcov_shm->cmp_diag.init_init_trace_count, errno);
				goto err_close_cmp;
			}

			kc->cmp_trace_buf = mmap(NULL,
				KCOV_CMP_BUFFER_SIZE * sizeof(unsigned long),
				PROT_READ | PROT_WRITE, MAP_SHARED,
				kc->cmp_fd, 0);
			if (kc->cmp_trace_buf == MAP_FAILED) {
				kcov_cmp_diag_record(&kcov_shm->cmp_diag.init_mmap_errno,
					&kcov_shm->cmp_diag.init_mmap_count, errno);
				kc->cmp_trace_buf = NULL;
				goto err_close_cmp;
			}

			/* Probe KCOV_TRACE_CMP support.  An older kernel
			 * without CMP returns -ENOTSUPP from ENABLE; tear
			 * down the cmp fd and leave cmp_capable = false. */
			if (ioctl(kc->cmp_fd, KCOV_ENABLE, KCOV_TRACE_CMP) < 0) {
				kcov_cmp_diag_record(&kcov_shm->cmp_diag.init_enable_errno,
					&kcov_shm->cmp_diag.init_enable_count, errno);
				goto err_unmap_cmp;
			}
			if (ioctl(kc->cmp_fd, KCOV_DISABLE, 0) < 0) {
				kcov_cmp_diag_record(&kcov_shm->cmp_diag.init_disable_errno,
					&kcov_shm->cmp_diag.init_disable_count, errno);
				goto err_unmap_cmp;
			}

			kc->cmp_capable = true;
			track_shared_region((unsigned long)kc->cmp_trace_buf,
				KCOV_CMP_BUFFER_SIZE * sizeof(unsigned long));
		}
	}

	/*
	 * Pick this child's collection mode for its lifetime.  Gated on
	 * cmp_capable so a kernel without KCOV_TRACE_CMP (or any failure
	 * in the probe above) degrades cleanly to PC-only across the
	 * fleet — KCOV_MODE_CMP is only reachable when the cmp fd is
	 * actually usable.  rand() % N has bias O(1/RAND_MAX) for the
	 * small N (4) used here; the population mix doesn't need
	 * cryptographic uniformity.
	 */
	if (kc->cmp_capable && (rand() % KCOV_CMP_CHILD_RECIPROCAL) == 0)
		kc->mode = KCOV_MODE_CMP;
	else
		kc->mode = KCOV_MODE_PC;
	return;

err_unmap_cmp:
	munmap(kc->cmp_trace_buf,
		KCOV_CMP_BUFFER_SIZE * sizeof(unsigned long));
	kc->cmp_trace_buf = NULL;
err_close_cmp:
	close(kc->cmp_fd);
	kc->cmp_fd = -1;
	return;

err_free_dedup:
	free(kc->dedup);
	kc->dedup = NULL;
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

void kcov_enable_trace(struct kcov_child *kc)
{
	if (kc == NULL || !kc->active)
		return;

	__atomic_store_n(&kc->trace_buf[0], 0, __ATOMIC_RELAXED);
	if (ioctl(kc->fd, KCOV_ENABLE, KCOV_TRACE_PC) < 0)
		kc->active = false;
}

void kcov_enable_cmp(struct kcov_child *kc)
{
	if (kc == NULL || !kc->cmp_capable)
		return;

	__atomic_store_n(&kc->cmp_trace_buf[0], 0, __ATOMIC_RELAXED);
	if (ioctl(kc->cmp_fd, KCOV_ENABLE, KCOV_TRACE_CMP) < 0) {
		/* Runtime failure on a previously-probed-good fd.  Leave
		 * kc->active alone — PC tracing on the other fd is
		 * independent and still valid; just stop attempting CMP.
		 * The early-return at the top of this function fires once
		 * cmp_capable flips to false, so the shm record gets one
		 * bump per child instead of spamming per-syscall. */
		kcov_cmp_diag_record(&kcov_shm->cmp_diag.runtime_enable_errno,
			&kcov_shm->cmp_diag.runtime_enable_count, errno);
		kc->cmp_capable = false;
		return;
	}
	kc->cmp_enabled_this_call = true;
}

void kcov_enable_remote(struct kcov_child *kc, unsigned int child_id)
{
	struct kcov_remote_arg arg = {0};

	if (kc == NULL || !kc->active || !kc->remote_capable)
		return;

	__atomic_store_n(&kc->trace_buf[0], 0, __ATOMIC_RELAXED);

	arg.trace_mode = KCOV_TRACE_PC;
	arg.area_size = KCOV_TRACE_SIZE;
	arg.num_handles = 0;
	arg.common_handle = KCOV_SUBSYSTEM_COMMON | (child_id + 1);

	if (ioctl(kc->fd, KCOV_REMOTE_ENABLE, &arg) < 0) {
		/* Fall back to per-thread mode if remote fails at runtime. */
		kc->remote_capable = false;
		if (ioctl(kc->fd, KCOV_ENABLE, KCOV_TRACE_PC) < 0)
			kc->active = false;
	}
}

void kcov_disable(struct kcov_child *kc)
{
	if (kc == NULL)
		return;

	/* Mode is fixed per child at init (see kcov_init_child), so only
	 * one of the two fds is ever enabled per syscall.  Branching here
	 * keeps a CMP-mode child from spamming KCOV_DISABLE -EINVAL on the
	 * PC fd every call (and a PC-mode child from spamming it on the cmp
	 * fd).  The kernel's one-`t->kcov`-per-task rule makes this
	 * exclusive: simultaneously enabling both fds returns -EBUSY on
	 * the second enable, so a child only ever has one fd active. */
	if (kc->mode == KCOV_MODE_PC) {
		if (kc->fd >= 0 && kc->trace_buf != NULL)
			ioctl(kc->fd, KCOV_DISABLE, 0);
	} else if (kc->cmp_fd >= 0 && kc->cmp_trace_buf != NULL &&
		   kc->cmp_enabled_this_call) {
		/* cmp_enabled_this_call gate preserves the pre-existing
		 * defence against a runtime KCOV_TRACE_CMP enable failure
		 * mid-run flipping cmp_capable=false — the disable then
		 * knows not to fire on an fd the kernel never enabled. */
		ioctl(kc->cmp_fd, KCOV_DISABLE, 0);
		kc->cmp_enabled_this_call = false;
	}
}

/*
 * Hash a kernel PC value into an edge index.
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
static unsigned int pc_to_edge(unsigned long pc)
{
	pc ^= pc >> 33;
	pc *= 0xff51afd7ed558ccdUL;
	pc ^= pc >> 33;
	pc *= 0xc4ceb9fe1a85ec53UL;
	pc ^= pc >> 33;
	return (unsigned int)(pc & (KCOV_NUM_EDGES - 1));
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
	uint32_t generation)
{
	unsigned int slot = (edge * 0x9E3779B1U) & KCOV_DEDUP_MASK;
	unsigned int probe;

	for (probe = 0; probe < KCOV_DEDUP_MAX_PROBE; probe++) {
		struct kcov_dedup_slot *s = &dedup[slot];

		if (s->generation != generation) {
			s->generation = generation;
			s->edge_idx = edge;
			s->count = 1;
			return 1;
		}
		if (s->edge_idx == edge) {
			s->count++;
			return s->count;
		}
		slot = (slot + 1) & KCOV_DEDUP_MASK;
	}
	return 1;
}

bool kcov_collect(struct kcov_child *kc, unsigned int nr,
		  unsigned long *new_edge_count)
{
	unsigned long count;
	unsigned long idx;
	unsigned long call_nr;
	unsigned long edges_this_call = 0;
	bool found_new = false;

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
	if (count > KCOV_TRACE_SIZE - 1) {
		/* Kernel wanted to record more PCs than the buffer holds; the
		 * tail of this call's coverage was dropped.  Bump a counter so
		 * the post-mortem can show whether KCOV_TRACE_SIZE needs to
		 * grow again. */
		__atomic_fetch_add(&kcov_shm->trace_truncated, 1,
			__ATOMIC_RELAXED);
		count = KCOV_TRACE_SIZE - 1;
	}

	/*
	 * Invalidate the dedup table by bumping the generation counter — every
	 * slot whose generation doesn't match is implicitly empty.  On
	 * wraparound (every 2^32 calls, ~70 days at 700 calls/sec) we'd
	 * collide with stale slots carrying the now-recycled generation, so
	 * fall back to a one-shot wipe and restart at generation 1.
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
		unsigned long pc_val = kc->trace_buf[idx + 1];
		unsigned int edge = pc_to_edge(pc_val);
		unsigned int local_count = dedup_inc(kc->dedup, edge,
			kc->current_generation);
		unsigned int bucket = bucket_for_count(local_count);
		unsigned char mask, old;

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
		old = __atomic_fetch_or(&kcov_shm->bucket_seen[edge],
			mask, __ATOMIC_RELAXED);

		if (!(old & mask)) {
			__atomic_fetch_add(&kcov_shm->edges_found,
				1, __ATOMIC_RELAXED);
			edges_this_call++;
			found_new = true;
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
			/* Bump the per-syscall frontier-edge ring so the
			 * coverage-frontier picker (when active) can bias
			 * selection toward syscalls currently producing fresh
			 * coverage. */
			frontier_record_new_edge(nr);
		}
	}

	if (new_edge_count != NULL)
		*new_edge_count = edges_this_call;

	return found_new;
}

void kcov_collect_cmp(struct kcov_child *kc, unsigned int nr,
		      bool is_explorer, int strategy_at_pick)
{
	unsigned long count;

	if (kc == NULL || !kc->cmp_capable || kc->cmp_trace_buf == NULL)
		return;

	count = __atomic_load_n(&kc->cmp_trace_buf[0], __ATOMIC_RELAXED);
	if (count > KCOV_CMP_RECORDS_MAX) {
		/* Kernel wanted to record more comparisons than the cmp
		 * buffer holds; the tail was dropped.  Mirrors the PC-side
		 * trace_truncated counter. */
		__atomic_fetch_add(&kcov_shm->cmp_trace_truncated, 1,
			__ATOMIC_RELAXED);
		count = KCOV_CMP_RECORDS_MAX;
	}

	if (count == 0)
		return;

	cmp_hints_collect(kc->cmp_trace_buf, nr);
	bandit_cmp_observe(kc->cmp_trace_buf, nr, is_explorer, strategy_at_pick);

	__atomic_fetch_add(&kcov_shm->cmp_records_collected, count,
		__ATOMIC_RELAXED);
}

void kcov_get_cmp_records(struct kcov_child *kc,
			  struct kcov_cmp_record **out,
			  unsigned long *count)
{
	unsigned long n;

	*out = NULL;
	*count = 0;

	if (kc == NULL || !kc->cmp_capable || kc->cmp_trace_buf == NULL)
		return;

	n = __atomic_load_n(&kc->cmp_trace_buf[0], __ATOMIC_RELAXED);
	if (n > KCOV_CMP_RECORDS_MAX)
		n = KCOV_CMP_RECORDS_MAX;
	if (n == 0)
		return;

	*out = (struct kcov_cmp_record *)&kc->cmp_trace_buf[1];
	*count = n;
}

unsigned int kcov_syscall_cold_skip_pct(unsigned int nr)
{
	unsigned long edges, gap;
	unsigned int pct;

	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL)
		return 0;

	edges = __atomic_load_n(&kcov_shm->per_syscall_edges[nr],
		__ATOMIC_RELAXED);

	if (edges == 0) {
		/* Never produced an edge.  Until this syscall has had
		 * KCOV_COLD_THRESHOLD attempts of its own, leave it alone —
		 * total_calls grows from every other syscall too, so basing
		 * the cutoff on total_calls would prematurely retire any
		 * syscall that the dispatch loop happens to under-pick.
		 * Once it has clearly had a fair shot, skip aggressively. */
		gap = __atomic_load_n(&kcov_shm->per_syscall_calls[nr],
			__ATOMIC_RELAXED);
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
	edges_now = __atomic_load_n(&kcov_shm->edges_found, __ATOMIC_RELAXED);

	/* Arm the window on the first call so any pre-existing edge count
	 * (e.g. from the warm-up phase before main_loop entry) is not
	 * mis-attributed to the first 10-minute window. */
	if (!kcov_shm->plateau_armed) {
		kcov_shm->plateau_window_start = now;
		kcov_shm->plateau_prev_edges = edges_now;
		kcov_shm->plateau_armed = true;
		return;
	}

	if ((now - kcov_shm->plateau_window_start) < KCOV_PLATEAU_WINDOW_SEC)
		return;

	delta = (edges_now >= kcov_shm->plateau_prev_edges)
		? edges_now - kcov_shm->plateau_prev_edges : 0;
	kcov_shm->plateau_last_window_delta = delta;
	kcov_shm->plateau_prev_edges = edges_now;
	kcov_shm->plateau_window_start = now;

	if (delta < KCOV_PLATEAU_RATE_THRESHOLD) {
		/* Edge-triggered: emit the warning, bump the transition
		 * counter, and fire the auto-response hook only when we cross
		 * from healthy into PLATEAU.  Subsequent ticks while still in
		 * plateau stay silent so the operator's stats.log gets one
		 * line per episode rather than one per 600s window. */
		if (!kcov_shm->plateau_active) {
			kcov_shm->plateau_active = true;
			kcov_shm->plateau_entered_at = now;
			__atomic_fetch_add(&shm->stats.plateau_entered, 1,
					   __ATOMIC_RELAXED);
			stats_log_write("PLATEAU: edge-discovery rate %lu edges/%ds < threshold (%d) sustained for >=%d minutes (bandit may be in local minimum, consider intervention)\n",
					delta, KCOV_PLATEAU_WINDOW_SEC,
					KCOV_PLATEAU_RATE_THRESHOLD,
					KCOV_PLATEAU_WINDOW_SEC / 60);
			strategy_plateau_response();
			/* Lock in the current bitmap on plateau entry --
			 * discovery has stalled, so the bucket_seen table
			 * is at its high-water mark for this run.  Snapshot
			 * even if the periodic cadence wouldn't have fired
			 * yet; bypass the gate via a one-shot. */
			kcov_bitmap_maybe_snapshot();
		}
	} else if (kcov_shm->plateau_active) {
		long minutes = (now - kcov_shm->plateau_entered_at) / 60;

		kcov_shm->plateau_active = false;
		kcov_shm->plateau_entered_at = 0;
		__atomic_fetch_add(&shm->stats.plateau_exited, 1,
				   __ATOMIC_RELAXED);
		stats_log_write("PLATEAU CLEARED: edge-discovery rate %lu edges/%ds (plateau lasted %ld minutes)\n",
				delta, KCOV_PLATEAU_WINDOW_SEC, minutes);
	}
}

/*
 * Warm-start persistence for kcov_shm->bucket_seen[] + edges_found.
 *
 * Layout: a fixed header followed by KCOV_NUM_EDGES bytes of bucket_seen
 * payload.  Atomic .tmp + rename on save mirrors effector-map / healer /
 * minicorpus.  No __attribute__((packed)) -- the field sequence below is
 * already naturally aligned on the LP64 ABIs trinity targets.
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
#define KCOV_BITMAP_FILE_VERSION	1U

struct kcov_bitmap_file_header {
	uint32_t magic;
	uint32_t version;
	uint32_t num_edges;
	uint32_t num_buckets;
	uint64_t edges_found;
	uint32_t payload_crc32;
	uint32_t pad;
	uint8_t  kallsyms_sha256[32];
};

/* Plain CRC32 (IEEE 802.3 polynomial, reflected).  Same algorithm
 * effector-map / minicorpus / healer use; kept local so a future
 * divergence in any one persistence format's checksum doesn't ripple
 * across the others. */
static uint32_t kcov_bitmap_crc32(const void *buf, size_t len)
{
	static uint32_t table[256];
	static bool table_built;
	const uint8_t *p = buf;
	uint32_t crc = 0xffffffffU;
	size_t i;

	if (!table_built) {
		uint32_t c;
		unsigned int n, k;

		for (n = 0; n < 256; n++) {
			c = n;
			for (k = 0; k < 8; k++)
				c = (c & 1) ? (0xedb88320U ^ (c >> 1)) : (c >> 1);
			table[n] = c;
		}
		table_built = true;
	}

	for (i = 0; i < len; i++)
		crc = table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);

	return crc ^ 0xffffffffU;
}

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

static ssize_t kcov_bitmap_write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t left = len;

	while (left > 0) {
		ssize_t n = write(fd, p, left);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += n;
		left -= n;
	}
	return (ssize_t)len;
}

static ssize_t kcov_bitmap_read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t left = len;

	while (left > 0) {
		ssize_t n = read(fd, p, left);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		p += n;
		left -= n;
	}
	return (ssize_t)(len - left);
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
	unsigned long edges_now;
	char tmppath[PATH_MAX];
	int fd;
	int ret;

	if (path == NULL || kcov_shm == NULL)
		return false;

	edges_now = __atomic_load_n(&kcov_shm->edges_found, __ATOMIC_RELAXED);
	if (edges_now == kcov_bitmap_edges_at_last_save) {
		output(0, "kcov-bitmap: snapshot skipped, no new edges since last save\n");
		return true;
	}

	memset(&hdr, 0, sizeof(hdr));
	if (!kcov_get_kernel_fp(hdr.kallsyms_sha256))
		return false;

	hdr.magic = KCOV_BITMAP_FILE_MAGIC;
	hdr.version = KCOV_BITMAP_FILE_VERSION;
	hdr.num_edges = KCOV_NUM_EDGES;
	hdr.num_buckets = KCOV_NUM_BUCKETS;
	hdr.edges_found = edges_now;
	hdr.payload_crc32 = kcov_bitmap_crc32(kcov_shm->bucket_seen,
					      KCOV_NUM_EDGES);

	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
		       path, (int)getpid());
	if (ret < 0 || (size_t)ret >= sizeof(tmppath))
		return false;

	fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return false;

	/* Neutralise any fuzzer-installed umask so the save mode is 0644. */
	if (fchmod(fd, 0644) != 0) {
		(void)close(fd);
		(void)unlink(tmppath);
		return false;
	}

	if (kcov_bitmap_write_all(fd, &hdr, sizeof(hdr)) < 0)
		goto fail;
	if (kcov_bitmap_write_all(fd, kcov_shm->bucket_seen,
				  KCOV_NUM_EDGES) < 0)
		goto fail;
	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		(void)unlink(tmppath);
		return false;
	}
	if (rename(tmppath, path) != 0) {
		(void)unlink(tmppath);
		return false;
	}
	kcov_bitmap_edges_at_last_save = edges_now;
	return true;

fail:
	(void)close(fd);
	(void)unlink(tmppath);
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

	n = kcov_bitmap_read_all(fd, &hdr, sizeof(hdr));
	if (n != (ssize_t)sizeof(hdr)) {
		output(0, "kcov-bitmap: header truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, n, sizeof(hdr));
		(void)close(fd);
		return false;
	}

	if (hdr.magic != KCOV_BITMAP_FILE_MAGIC) {
		output(0, "kcov-bitmap: file magic 0x%08x != expected 0x%08x at %s -- cold start\n",
		       hdr.magic, KCOV_BITMAP_FILE_MAGIC, path);
		(void)close(fd);
		return false;
	}
	if (hdr.version != KCOV_BITMAP_FILE_VERSION) {
		output(0, "kcov-bitmap: file version %u != expected %u at %s -- cold start\n",
		       hdr.version, KCOV_BITMAP_FILE_VERSION, path);
		(void)close(fd);
		return false;
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

	/* Stage into a scratch buffer so a CRC failure doesn't leave the
	 * shared bitmap half-overwritten with garbage. */
	scratch = malloc(KCOV_NUM_EDGES);
	if (scratch == NULL) {
		output(0, "kcov-bitmap: scratch alloc fail (%zu bytes) -- cold start\n",
		       (size_t)KCOV_NUM_EDGES);
		(void)close(fd);
		return false;
	}
	n = kcov_bitmap_read_all(fd, scratch, KCOV_NUM_EDGES);
	if (n != (ssize_t)KCOV_NUM_EDGES) {
		output(0, "kcov-bitmap: payload truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, n, (size_t)KCOV_NUM_EDGES);
		free(scratch);
		(void)close(fd);
		return false;
	}
	(void)close(fd);

	want_crc = kcov_bitmap_crc32(scratch, KCOV_NUM_EDGES);
	if (want_crc != hdr.payload_crc32) {
		output(0, "kcov-bitmap: skipping warm-start of %s -- CRC mismatch\n",
		       path);
		free(scratch);
		return false;
	}

	memcpy(kcov_shm->bucket_seen, scratch, KCOV_NUM_EDGES);
	free(scratch);
	__atomic_store_n(&kcov_shm->edges_found, hdr.edges_found,
			 __ATOMIC_RELAXED);
	/* Seed the dirty-bit baseline so a load-then-immediate-exit cycle
	 * skips the redundant end-of-run save. */
	kcov_bitmap_edges_at_last_save = hdr.edges_found;
	output(0, "kcov-bitmap: loaded %lu edges from %s\n",
	       (unsigned long)hdr.edges_found, path);
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
