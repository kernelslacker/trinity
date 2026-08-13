/*
 * mseal_transition_matrix -- three-VMA arena mseal prohibited-transition coverage.
 *
 * Builds a three-VMA arena (fully-sealed / partially-sealed / unsealed gap),
 * writes per-page canary bytes into every page, then systematically attempts
 * every class of operation that mseal(2) prohibits against sealed and
 * partially-sealed ranges.  The oracle goes beyond checking return codes:
 * after every operation that SHOULD have failed the canary bytes are
 * re-verified so that a silent madvise content-wipe, a MAP_FIXED
 * replacement or a munmap-then-fault is caught even when the kernel reports
 * a spurious success only some of the time.
 *
 * A parallel reader thread continuously faults pages in the fully-sealed
 * VMA while the main matrix loop applies the prohibited transitions; this
 * races the kernel's VMA-lock path against the fault path.
 *
 * Arena layout (all anonymous, PROT_READ|PROT_WRITE at map time):
 *
 *   VMA_A  ARENA_PAGES pages   fully sealed with mseal(2)
 *   VMA_B  ARENA_PAGES pages   first ARENA_PAGES/2 pages sealed, rest not
 *   VMA_C  ARENA_PAGES/2 pages never sealed (gap / unsealed control)
 *
 * Each page in VMA_A and VMA_B is filled with the byte
 *   CANARY_FILL(page_idx) = 0xA5 ^ (page_idx & 0xFF)
 * before sealing.  The oracle re-reads that pattern after every
 * prohibited-op attempt and bumps mseal_content_oracle_fail on mismatch.
 *
 * All mutations run inside a forked helper; sealed pages cannot be
 * munmap'd, so the helper's AS is intentionally "dirty" and cleaned up by
 * the kernel on _exit().  The parent (trinity child) never seals any of
 * its own mappings.
 *
 * Counters published to shm:
 *   shm->stats.childop.setup_accepted[op]    arena mapped and sealed OK
 *   shm->stats.childop.data_path[op]         operation matrix entered
 *   shm->stats.diag.mseal_content_oracle_fail canary mismatch post-op
 *   shm->stats.diag.mseal_unexpected_success  prohibited op returned 0
 */

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "childop-outcome.h"
#include "childops-util.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "signals.h"
#include "trinity.h"
#include "utils.h"
#include "utils-mem.h"

#include "kernel/mman.h"

/* ------------------------------------------------------------------ */
/* Tunables                                                             */
/* ------------------------------------------------------------------ */

#define ARENA_PAGES	8U		/* pages per primary VMA */
#define RACE_ITERS	200U		/* reader cycles during race phase */
#define MATRIX_ITERS	3U		/* repeated passes over the matrix  */

/* Canary fill byte for page p */
#define CANARY_FILL(p)	((uint8_t)(0xA5u ^ ((unsigned int)(p) & 0xFFu)))

/* Budget cap (200 ms) so alarm(1) in child.c is never tripped */
#define BUDGET_NS	200000000L

/* ------------------------------------------------------------------ */
/* mseal(2) raw wrapper -- glibc may not expose it yet                  */
/* ------------------------------------------------------------------ */

static long do_mseal(unsigned long addr, size_t len, unsigned long flags)
{
	return syscall(__NR_mseal, (long)addr, (long)len, (long)flags);
}

/* ------------------------------------------------------------------ */
/* Canary helpers                                                       */
/* ------------------------------------------------------------------ */

static void fill_arena_canary(unsigned char *base, unsigned int npages)
{
	unsigned int p;

	for (p = 0; p < npages; p++) {
		uint8_t fill = CANARY_FILL(p);
		memset(base + (size_t)p * page_size, fill, page_size);
	}
}

/*
 * Returns true iff all canary bytes in [base, base + npages*page_size)
 * match the expected pattern.  Reads every byte so a partial wipe from
 * a madvise that succeeded when it shouldn't have is caught immediately.
 */
static bool verify_arena_canary(const unsigned char *base, unsigned int npages)
{
	unsigned int p;

	for (p = 0; p < npages; p++) {
		uint8_t expected = CANARY_FILL(p);
		const unsigned char *pg = base + (size_t)p * page_size;
		size_t b;

		for (b = 0; b < page_size; b++) {
			if (pg[b] != expected)
				return false;
		}
	}
	return true;
}

/* ------------------------------------------------------------------ */
/* Race thread: continuously reads VMA_A to keep pages faulted in      */
/* ------------------------------------------------------------------ */

struct reader_ctx {
	volatile unsigned char	*base;
	unsigned int		 npages;
	volatile int		 stop;
	unsigned long		 read_count;
};

static void *reader_thread(void *arg)
{
	struct reader_ctx *ctx = arg;
	unsigned long count = 0;

	while (!ctx->stop) {
		/* Touch a random page to exercise the fault path */
		unsigned int p = rnd_modulo_u32(ctx->npages);
		volatile unsigned char *ptr =
			ctx->base + (size_t)p * page_size;
		/* Volatile read; discard value -- just need the fault */
		(void)*ptr;
		count++;
	}
	ctx->read_count = count;
	return NULL;
}

/* ------------------------------------------------------------------ */
/* Oracle check + counter bumps (called from inside the helper)        */
/* ------------------------------------------------------------------ */

static void oracle_check(const unsigned char *sealed_base, unsigned int npages,
			 int ret, int err, const char *opname)
{
	if (ret == 0) {
		/* Prohibited op succeeded -- bump counter and bail  */
		output(0, /* check-static: child-output-ok */ "mseal_transition: UNEXPECTED SUCCESS: %s ret=0 "
		       "on sealed range %p+%lu\n",
		       opname, (void *)sealed_base,
		       (unsigned long)npages * page_size); /* check-static: child-output-ok */
		__atomic_add_fetch(&shm->stats.diag.mseal_unexpected_success,
				   1, __ATOMIC_RELAXED);
		return;
	}
	(void)err;

	/* Op failed (expected).  Verify content integrity. */
	if (!verify_arena_canary(sealed_base, npages)) {
		output(0, /* check-static: child-output-ok */ "mseal_transition: ORACLE FAIL: %s canary mismatch "
		       "on sealed range %p+%lu\n",
		       opname, (void *)sealed_base,
		       (unsigned long)npages * page_size);
		__atomic_add_fetch(&shm->stats.diag.mseal_content_oracle_fail,
				   1, __ATOMIC_RELAXED);
	}
}

/* ------------------------------------------------------------------ */
/* Matrix: attempt every prohibited-op class on sealed ranges          */
/* ------------------------------------------------------------------ */

static void run_matrix(unsigned char *vma_a, unsigned char *vma_b,
		       unsigned char *vma_c,
		       unsigned int a_pages, unsigned int b_pages,
		       unsigned int c_pages)
{
	unsigned int half_b    = b_pages / 2;	/* sealed portion of VMA_B  */
	size_t       a_size    = (size_t)a_pages   * page_size;
	size_t       b_size    = (size_t)b_pages   * page_size;
	size_t       b_half    = (size_t)half_b    * page_size;
	size_t       c_size    = (size_t)c_pages   * page_size;
	unsigned int iter;
	int          ret;

	(void)b_size;	/* used only implicitly via pointer arithmetic */
	(void)c_size;

	for (iter = 0; iter < MATRIX_ITERS; iter++) {

		/* --- munmap against fully-sealed range ------------------- */
		ret = munmap(vma_a, page_size);
		oracle_check(vma_a, a_pages, ret, errno, "munmap-vma_a-pg1");

		ret = munmap(vma_a, a_size);
		oracle_check(vma_a, a_pages, ret, errno, "munmap-vma_a-full");

		/* --- munmap partial overlap: sealed + unsealed ----------- */
		/*
		 * VMA_B: first half_b pages sealed, rest not.
		 * munmap the whole VMA_B range.  mseal should reject it
		 * because the range overlaps the sealed portion.
		 */
		ret = munmap(vma_b, b_half);
		oracle_check(vma_b, half_b, ret, errno,
			     "munmap-vma_b-sealed-half");

		/* --- MAP_FIXED replacement over sealed range -------------- */
		{
			void *p;

			p = mmap(vma_a, page_size,
				 PROT_READ | PROT_WRITE,
				 MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
				 -1, 0);
			ret = (p == MAP_FAILED) ? -1 : 0;
			oracle_check(vma_a, a_pages, ret, errno,
				     "mmap-fixed-vma_a");
		}

		/* MAP_FIXED over the sealed half of VMA_B */
		{
			void *p;

			p = mmap(vma_b, page_size,
				 PROT_READ | PROT_WRITE,
				 MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
				 -1, 0);
			ret = (p == MAP_FAILED) ? -1 : 0;
			oracle_check(vma_b, half_b, ret, errno,
				     "mmap-fixed-vma_b-sealed");
		}

		/* --- mprotect against sealed range ----------------------- */
		ret = mprotect(vma_a, page_size, PROT_READ);
		oracle_check(vma_a, a_pages, ret, errno,
			     "mprotect-vma_a-RDONLY");

		ret = mprotect(vma_a, a_size, PROT_NONE);
		oracle_check(vma_a, a_pages, ret, errno,
			     "mprotect-vma_a-NONE");

		ret = mprotect(vma_a, a_size, PROT_READ | PROT_WRITE | PROT_EXEC);
		oracle_check(vma_a, a_pages, ret, errno,
			     "mprotect-vma_a-RWX");

		ret = mprotect(vma_b, b_half, PROT_READ);
		oracle_check(vma_b, half_b, ret, errno,
			     "mprotect-vma_b-sealed-half");

		/* --- mremap: expand sealed range ------------------------- */
		{
			void *p;

			/* MREMAP_MAYMOVE -- kernel must refuse the mseal source */
			p = mremap(vma_a, page_size, page_size * 2,
				   MREMAP_MAYMOVE);
			ret = (p == MAP_FAILED) ? -1 : 0;
			oracle_check(vma_a, a_pages, ret, errno,
				     "mremap-expand-vma_a");
		}

		/* mremap: fixed-move sealed page to VMA_C area */
		{
			void *p;

			p = mremap(vma_a, page_size, page_size,
				   MREMAP_MAYMOVE | MREMAP_FIXED,
				   vma_c);
			ret = (p == MAP_FAILED) ? -1 : 0;
			oracle_check(vma_a, a_pages, ret, errno,
				     "mremap-fixed-vma_a-to-vma_c");
		}

		/* --- remap_file_pages on sealed range -------------------- */
		/*
		 * remap_file_pages(2) is deprecated (internally reimplemented
		 * as mmap+MAP_FIXED since Linux 3.16) but mseal should still
		 * fire the EACCES check before the remapping proceeds.
		 * Anonymous mappings also produce EINVAL from the ABI check;
		 * either error is "not 0" so oracle_check handles both.
		 */
		ret = (int)syscall(__NR_remap_file_pages,
				   (unsigned long)vma_a, (unsigned long)page_size,
				   0UL, 1UL, 0UL);
		oracle_check(vma_a, a_pages, ret, errno,
			     "remap_file_pages-vma_a");

		/* --- destructive madvise on sealed range ----------------- */
		ret = madvise(vma_a, a_size, MADV_DONTNEED);
		oracle_check(vma_a, a_pages, ret, errno,
			     "madvise-DONTNEED-vma_a");

		ret = madvise(vma_a, a_size, MADV_FREE);
		oracle_check(vma_a, a_pages, ret, errno,
			     "madvise-FREE-vma_a");

		ret = madvise(vma_a, a_size, MADV_WIPEONFORK);
		oracle_check(vma_a, a_pages, ret, errno,
			     "madvise-WIPEONFORK-vma_a");

		ret = madvise(vma_b, b_half, MADV_DONTNEED);
		oracle_check(vma_b, half_b, ret, errno,
			     "madvise-DONTNEED-vma_b-sealed");

		/*
		 * MADV_PAGEOUT / MADV_COLD -- kernel ≥ 5.4; mseal blocks
		 * these on sealed ranges too.  Use raw madvise(2) via
		 * syscall so the libc wrapper's argument filtering doesn't
		 * convert an unknown advice to EINVAL before the kernel
		 * sees it.
		 */
		ret = (int)syscall(__NR_madvise,
				   (unsigned long)vma_a, (unsigned long)a_size,
				   (long)MADV_PAGEOUT);
		oracle_check(vma_a, a_pages, ret, errno,
			     "madvise-PAGEOUT-vma_a");

		ret = (int)syscall(__NR_madvise,
				   (unsigned long)vma_a, (unsigned long)a_size,
				   (long)MADV_COLD);
		oracle_check(vma_a, a_pages, ret, errno,
			     "madvise-COLD-vma_a");

		/* --- mixed gap: apply to range spanning sealed boundary -- */
		/*
		 * VMA_B second half (vma_b + b_half .. vma_b + b_size) is
		 * unsealed.  mprotect over the FULL VMA_B range must fail
		 * because it includes the sealed prefix.
		 */
		ret = mprotect(vma_b, b_size, PROT_READ);
		oracle_check(vma_b, half_b, ret, errno,
			     "mprotect-vma_b-full-spans-boundary");

		/*
		 * Apply a benign mprotect to the UNSEALED portion of VMA_B
		 * to confirm the unsealed part is still functional.  This
		 * must succeed; we don't run oracle_check on it (it's not a
		 * prohibited transition) but a failure here means mseal has
		 * spilled the sealed attribute onto the unsealed portion.
		 */
		{
			int r = mprotect(vma_b + b_half, b_size - b_half,
					 PROT_READ | PROT_WRITE);
			if (r != 0) {
				output(0, /* check-static: child-output-ok */
				       "mseal_transition: unsealed mprotect "
				       "failed errno=%d (mseal attribute "
				       "leak?)\n", errno);
				__atomic_add_fetch(
					&shm->stats.diag.mseal_content_oracle_fail,
					1, __ATOMIC_RELAXED);
			}
		}
	}
}

/* ------------------------------------------------------------------ */
/* Helper: runs inside forked child; returns for the parent            */
/* ------------------------------------------------------------------ */

static void __attribute__((noreturn))
run_helper(enum child_op_type op)
{
	unsigned int  a_pages = ARENA_PAGES;
	unsigned int  b_pages = ARENA_PAGES;
	unsigned int  c_pages = ARENA_PAGES / 2;
	size_t        a_size  = (size_t)a_pages * page_size;
	size_t        b_size  = (size_t)b_pages * page_size;
	size_t        c_size  = (size_t)c_pages * page_size;
	unsigned int  b_half  = b_pages / 2;
	size_t        b_seal  = (size_t)b_half * page_size;
	unsigned char *vma_a, *vma_b, *vma_c;
	long           seal_ret;
	pthread_t      rtid;
	struct reader_ctx rctx;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);

	/* --- allocate arena ----------------------------------------- */
	vma_a = mmap(NULL, a_size, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (vma_a == MAP_FAILED)
		_exit(1);

	vma_b = mmap(NULL, b_size, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (vma_b == MAP_FAILED) {
		(void)munmap(vma_a, a_size);
		_exit(1);
	}

	vma_c = mmap(NULL, c_size, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (vma_c == MAP_FAILED) {
		(void)munmap(vma_a, a_size);
		(void)munmap(vma_b, b_size);
		_exit(1);
	}

	/* Sanity: make sure none of these overlap shared trinity regions */
	if (range_overlaps_shared((unsigned long)vma_a, a_size) ||
	    range_overlaps_shared((unsigned long)vma_b, b_size) ||
	    range_overlaps_shared((unsigned long)vma_c, c_size)) {
		(void)munmap(vma_a, a_size);
		(void)munmap(vma_b, b_size);
		(void)munmap(vma_c, c_size);
		_exit(1);
	}

	/* --- write canaries before sealing --------------------------- */
	fill_arena_canary(vma_a, a_pages);
	fill_arena_canary(vma_b, b_pages);
	fill_arena_canary(vma_c, c_pages);	/* VMA_C stays unsealed */

	/* --- seal ---------------------------------------------------- */
	seal_ret = do_mseal((unsigned long)vma_a, a_size, 0);
	if (seal_ret != 0) {
		/* mseal unavailable or failed: clean up and exit */
		(void)munmap(vma_a, a_size);
		(void)munmap(vma_b, b_size);
		(void)munmap(vma_c, c_size);
		_exit(2);
	}

	/* Partial seal: first half of VMA_B */
	seal_ret = do_mseal((unsigned long)vma_b, b_seal, 0);
	if (seal_ret != 0) {
		/* Partial seal failed; VMA_A already sealed, can't unmap it */
		(void)munmap(vma_b, b_size);
		(void)munmap(vma_c, c_size);
		_exit(2);
	}

	/* Signal setup complete to parent via counter */
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/* ---- data-path counter ------------------------------------ */
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	/* --- launch reader thread ------------------------------------ */
	memset(&rctx, 0, sizeof(rctx));
	rctx.base   = (volatile unsigned char *)vma_a;
	rctx.npages = a_pages;
	rctx.stop   = 0;

	if (pthread_create(&rtid, NULL, reader_thread, &rctx) != 0) {
		/* Can't create thread -- run matrix without race */
		run_matrix(vma_a, vma_b, vma_c, a_pages, b_pages, c_pages);
		(void)munmap(vma_b, b_size);
		(void)munmap(vma_c, c_size);
		_exit(0);
	}

	/* --- operation matrix (races against reader thread) ---------- */
	run_matrix(vma_a, vma_b, vma_c, a_pages, b_pages, c_pages);

	/* Stop reader thread */
	__atomic_store_n(&rctx.stop, 1, __ATOMIC_RELEASE);
	(void)pthread_join(rtid, NULL);

	/* Clean up what we can (unsealed mappings only) */
	(void)munmap(vma_b + b_seal, b_size - b_seal);	/* unsealed tail of B */
	(void)munmap(vma_c, c_size);

	_exit(0);
}

/* ------------------------------------------------------------------ */
/* Childop entry point                                                  */
/* ------------------------------------------------------------------ */

bool mseal_transition_matrix(struct childdata *child)
{
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);
	struct timespec start;
	pid_t helper;
	int status;
	unsigned long direct_calls = 0;

	/*
	 * Quick kernel-support probe: mseal(0, 0, 0) should return 0 on
	 * kernels that implement it.  ENOSYS means the syscall is absent;
	 * latch off for the rest of the run so we don't spin on ENOSYS.
	 */
	direct_calls++;	/* do_mseal probe */
	if (do_mseal(0UL, 0UL, 0UL) == -1 && errno == ENOSYS) {
		if (valid_op)
			__atomic_add_fetch(
				&shm->stats.childop.latch_reason[op],
				CHILDOP_LATCH_UNSUPPORTED,
				__ATOMIC_RELAXED);
		childop_direct_syscalls_add(op, direct_calls);
		return false;
	}

	clock_gettime(CLOCK_MONOTONIC, &start);
	direct_calls++;	/* clock_gettime */

	direct_calls++;	/* fork */
	helper = fork();
	if (helper < 0) {
		childop_direct_syscalls_add(op, direct_calls);
		return true;
	}

	if (helper == 0) {
		/* Inside the forked helper -- never returns */
		run_helper(op);
		/* NOTREACHED */
	}

	/* Parent: wait for helper, bounded by BUDGET_NS */
	while (1) {
		pid_t r = waitpid_eintr(helper, &status, WNOHANG);
		direct_calls++;	/* waitpid */

		if (r == helper)
			break;
		if (r < 0 && errno != EINTR) {
			direct_calls++;	/* kill */
			(void)kill(helper, SIGKILL);
			direct_calls++;	/* waitpid */
			(void)waitpid_eintr(helper, &status, 0);
			break;
		}

		if (budget_elapsed_ns(&start, BUDGET_NS)) {
			direct_calls++;	/* clock_gettime inside budget_elapsed_ns */
			direct_calls++;	/* kill */
			(void)kill(helper, SIGKILL);
			direct_calls++;	/* waitpid */
			(void)waitpid_eintr(helper, &status, 0);
			break;
		}
		direct_calls++;	/* clock_gettime inside budget_elapsed_ns */

		{
			struct timespec ts = { 0, 1000000L };	/* 1 ms */
			(void)nanosleep(&ts, NULL);
			direct_calls++;	/* nanosleep */
		}
	}

	if (valid_op && direct_calls > 0)
		childop_direct_syscalls_add(op, direct_calls);
	return true;
}
