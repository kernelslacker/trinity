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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "cmp_hints.h"
#include "edgepair.h"
#include "kcov.h"
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

void kcov_init_global(void)
{
	int fd;

	/* Probe whether KCOV is available before allocating shared memory. */
	fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (fd < 0)
		return;
	close(fd);

	/*
	 * Stays alloc_shared() rather than alloc_shared_global().
	 * Children are the producers for every field in struct kcov_shared:
	 * kcov_collect() (called from random-syscall.c in child context after
	 * each syscall) writes to bucket_seen[] via fetch_or, bumps
	 * total_calls / remote_calls / total_pcs / edges_found, and updates
	 * the per_syscall_calls / per_syscall_edges / last_edge_at arrays.
	 * Freezing this region PROT_READ post-init would EFAULT every child's
	 * coverage update on the hot path and disable the fuzzer's coverage
	 * feedback loop entirely — the wild-write defence is incompatible
	 * with the region's intentional child-writability.
	 *
	 * Wild-write risk this leaves open: a child syscall whose user-buffer
	 * arg aliases into kcov_shm could let the kernel corrupt the
	 * bucket_seen table (false-positive coverage inflation, including
	 * spurious bucket bits) or the per-syscall counters (a bogus
	 * last_edge_at value would stick a syscall in or out of the
	 * cold-skip pool).  Diagnostics only; doesn't crash the parent.
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
	kc->remote_mode = false;
	kc->remote_capable = false;
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
		if (kc->cmp_fd >= 0) {
			if (ioctl(kc->cmp_fd, KCOV_INIT_TRACE,
					(unsigned long)KCOV_CMP_BUFFER_SIZE) < 0)
				goto err_close_cmp;

			kc->cmp_trace_buf = mmap(NULL,
				KCOV_CMP_BUFFER_SIZE * sizeof(unsigned long),
				PROT_READ | PROT_WRITE, MAP_SHARED,
				kc->cmp_fd, 0);
			if (kc->cmp_trace_buf == MAP_FAILED) {
				kc->cmp_trace_buf = NULL;
				goto err_close_cmp;
			}

			/* Probe KCOV_TRACE_CMP support.  An older kernel
			 * without CMP returns -ENOTSUPP from ENABLE; tear
			 * down the cmp fd and leave cmp_capable = false. */
			if (ioctl(kc->cmp_fd, KCOV_ENABLE, KCOV_TRACE_CMP) < 0)
				goto err_unmap_cmp;
			if (ioctl(kc->cmp_fd, KCOV_DISABLE, 0) < 0)
				goto err_unmap_cmp;

			kc->cmp_capable = true;
			track_shared_region((unsigned long)kc->cmp_trace_buf,
				KCOV_CMP_BUFFER_SIZE * sizeof(unsigned long));
		}
	}
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
		munmap(kc->trace_buf, KCOV_TRACE_SIZE * sizeof(unsigned long));
		kc->trace_buf = NULL;
	}
	if (kc->fd >= 0) {
		close(kc->fd);
		kc->fd = -1;
	}
	if (kc->cmp_trace_buf != NULL) {
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
		 * independent and still valid; just stop attempting CMP. */
		kc->cmp_capable = false;
	}
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

	if (kc->fd >= 0 && kc->trace_buf != NULL)
		ioctl(kc->fd, KCOV_DISABLE, 0);

	/* Always issue DISABLE on the cmp fd as well; it's a no-op when
	 * the fd was never enabled this call (effector-map calibration
	 * paths only go through kcov_enable_trace) and the kernel will
	 * just return -EINVAL, which we ignore. */
	if (kc->cmp_fd >= 0 && kc->cmp_trace_buf != NULL)
		ioctl(kc->cmp_fd, KCOV_DISABLE, 0);
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

bool kcov_collect(struct kcov_child *kc, unsigned int nr)
{
	unsigned long count;
	unsigned long idx;
	unsigned long call_nr;
	bool found_new = false;

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
		if (local_count > 1 && bucket == bucket_for_count(local_count - 1))
			continue;

		mask = (unsigned char)(1U << bucket);
		old = __atomic_fetch_or(&kcov_shm->bucket_seen[edge],
			mask, __ATOMIC_RELAXED);

		if (!(old & mask)) {
			__atomic_fetch_add(&kcov_shm->edges_found,
				1, __ATOMIC_RELAXED);
			found_new = true;
		}
	}

	__atomic_fetch_add(&kcov_shm->total_pcs, count, __ATOMIC_RELAXED);

	if (nr < MAX_NR_SYSCALL) {
		__atomic_fetch_add(&kcov_shm->per_syscall_calls[nr],
			1, __ATOMIC_RELAXED);
		if (found_new) {
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

	return found_new;
}

void kcov_collect_cmp(struct kcov_child *kc, unsigned int nr,
		      bool is_explorer)
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
	bandit_cmp_observe(kc->cmp_trace_buf, nr, is_explorer);

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
