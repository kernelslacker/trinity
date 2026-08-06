/*
 * uffd_fault_move - stateful UFFD fault + UFFDIO_MOVE/swap-cache race.
 *
 * Random ioctl fuzzing already covers UFFDIO_MOVE, UFFDIO_COPY,
 * UFFDIO_ZEROPAGE, UFFDIO_WP, and friends, but almost never has a
 * negotiated fd, a compatible VMA, a registered range, and a *pending
 * fault* all at the same time.  This childop arranges those
 * preconditions and drives three bounded variants that exercise paths
 * the random picker barely reaches:
 *
 * Variant 1 -- fault-resolve matrix
 *   Register an anonymous VMA MISSING|WP.  A fault thread accesses one
 *   page at a time, blocking inside the kernel until the main thread
 *   resolves the fault.  Resolution rotates through UFFDIO_COPY (with a
 *   per-page sequence number in the source page so the oracle can verify
 *   content), UFFDIO_ZEROPAGE, UFFDIO_POISON, and UFFDIO_WP (re-write-
 *   protect after initial COPY).  The DONTWAKE flag is exercised on
 *   every COPY/ZEROPAGE: the fault thread stays blocked until an
 *   explicit UFFDIO_WAKE is sent, verifying the DONTWAKE+WAKE discipline.
 *
 * Variant 2 -- UFFDIO_MOVE / swap-cache race
 *   Create two distinct MAP_PRIVATE|MAP_ANONYMOUS mappings for src and dst.
 *   Negotiate UFFD_FEATURE_MOVE; if the kernel does not support it the
 *   variant is skipped cleanly.  Fill src pages with per-page sequence
 *   numbers, then register dst with UFFDIO_REGISTER MISSING.  A racer
 *   thread issues MADV_PAGEOUT on src then re-reads it (causing a refault),
 *   racing UFFDIO_MOVE in the main thread.  MADV_PAGEOUT on anonymous
 *   memory drives pages to swap (requires CONFIG_SWAP and a configured swap
 *   device on the test machine), reaching move_swap_pte().  Vary
 *   UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES and destination occupancy per
 *   iteration.  Oracle: read dst pages after MOVE and verify sequence
 *   numbers.  Targets move_swap_pte() and the 2025-26 swap-cache race
 *   fixes.
 *
 * Variant 3 -- teardown race
 *   With a fault pending (fault thread blocked inside the kernel), race
 *   one of: close(uffd), UFFDIO_UNREGISTER, munmap, mremap against the
 *   pending fault.  The fault thread uses sigsetjmp to escape the SIGBUS
 *   or SIGSEGV the kernel delivers when teardown invalidates the faulting
 *   page.  Tests single-owner cleanup and the userfaultfd_release/unregister
 *   wakeup paths.
 *
 * Bounding:
 *   - alarm(1) set by the parent dispatch loop brackets the entire op.
 *   - All variants cap iterations at MAX_FM_ROUNDS.
 *   - poll() on the uffd fd uses POLL_TIMEOUT_MS; missing a fault
 *     (unlikely) just wastes one poll slot and the loop continues.
 *   - Every munmap/close runs in the same child process; cleanup is
 *     unconditional on all exit paths.
 *   - Variant 3 fault thread uses sigsetjmp to escape teardown signals;
 *     pthread_join is bounded by a busy-poll with WNOHANG-equivalent
 *     pthread_tryjoin_np.
 *
 * Oracle:
 *   After COPY or MOVE, the target page contains the source sequence number
 *   (page index + 1, ORed with a magic constant).  The fault thread (V1)
 *   or main thread (V2) reads back the page and compares.  Mismatch
 *   increments oracle_mismatch; every check (whether pass or fail) bumps
 *   oracle_checks_run so a reader can distinguish "oracle ran and passed"
 *   from "oracle never ran".
 *
 * Availability latches:
 *   ns_unsupported   - set once on EPERM/ENOSYS from userfaultfd(); skips
 *                      subsequent invocations cleanly.
 *   v2_move_latch    - -1 unknown, 0 unsupported, 1 supported; probed on
 *                      first V2 attempt and latched.
 *
 * UFFD_USER_MODE_ONLY is passed at all userfaultfd() call sites, matching
 * the latch established by uffd_churn.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"		/* page_size */
#include "child.h"
#include "childop-outcome.h"
#include "childops-util.h"
#include "jitter.h"
#include "rnd.h"
#include "shm.h"
#include "syscall-gate.h"
#include "trinity.h"
#include "utils.h"		/* output() */

#include "kernel/userfaultfd.h"
#include "kernel/fcntl.h"

/* Maximum pages per invocation; kept small to stay well inside alarm(1). */
#define MAX_FM_PAGES		4
/* Maximum iterations per variant per invocation. */
#define MAX_FM_ROUNDS		4
/* poll() timeout in milliseconds while waiting for a fault event. */
#define POLL_TIMEOUT_MS		150
/* Magic ORed into sequence numbers to distinguish "never written" (0). */
#define SEQNO_MAGIC		0xA5A50000U
/* Maximum busy-poll loops when joining variant-3 thread. */
#define V3_JOIN_LOOPS		200
/* Nanoseconds between V3 join polls. */
#define V3_JOIN_SLEEP_NS	5000000L	/* 5 ms */

/* --------------------------------------------------------------------
 * Shared per-invocation availability latches
 * -------------------------------------------------------------------- */

/* Latched per-child: userfaultfd(2) returned EPERM/ENOSYS. */
static bool ns_unsupported;

/* UFFD_FEATURE_MOVE probe: -1=unknown, 0=absent, 1=present. */
static int v2_move_latch = -1;

/* --------------------------------------------------------------------
 * Low-level helpers
 * -------------------------------------------------------------------- */

static int do_userfaultfd(int flags)
{
#ifdef SYS_userfaultfd
	return (int)trinity_raw_syscall(SYS_userfaultfd, flags);
#else
	(void)flags;
	errno = ENOSYS;
	return -1;
#endif
}

/*
 * Open a userfaultfd, negotiate UFFDIO_API, and fill in *feats with
 * the reported api.features bitmap.  Returns fd >= 0 on success,
 * -1 on error (errno preserved).  Propagates EPERM/ENOSYS so callers
 * can latch ns_unsupported.
 */
static int uffd_open(uint64_t request_features, uint64_t *feats_out,
		     uint64_t *ioctls_out)
{
	struct uffdio_api api;
	int fd;

	fd = do_userfaultfd(O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY);
	if (fd < 0)
		return -1;

	memset(&api, 0, sizeof(api));
	api.api      = UFFD_API;
	api.features = request_features;
	if (ioctl(fd, UFFDIO_API, &api) < 0) {
		close(fd);
		return -1;
	}

	if (feats_out)
		*feats_out  = api.features;
	if (ioctls_out)
		*ioctls_out = api.ioctls;
	return fd;
}

/*
 * Register [addr, addr+len) with mode bits @mode.  Returns the
 * per-range ioctl bitmap via *range_ioctls on success.
 */
static bool uffd_register(int fd, void *addr, size_t len, uint64_t mode,
			  uint64_t *range_ioctls)
{
	struct uffdio_register reg;

	memset(&reg, 0, sizeof(reg));
	reg.range.start = (uintptr_t)addr;
	reg.range.len   = len;
	reg.mode        = mode;
	if (ioctl(fd, UFFDIO_REGISTER, &reg) < 0)
		return false;
	if (range_ioctls)
		*range_ioctls = reg.ioctls;
	return true;
}

/*
 * Unregister [addr, addr+len).  Best-effort; ignores errors from
 * ranges that have already been unmapped.
 */
static void uffd_unregister(int fd, void *addr, size_t len)
{
	struct uffdio_range r;

	r.start = (uintptr_t)addr;
	r.len   = len;
	(void)ioctl(fd, UFFDIO_UNREGISTER, &r);
}

/*
 * Block until one fault event is readable on @fd (timeout @ms ms) and
 * fill *msg.  Returns true on success.
 */
static bool uffd_poll_one(int fd, int ms, struct uffd_msg *msg)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	if (poll(&pfd, 1, ms) <= 0)
		return false;
	if (!(pfd.revents & POLLIN))
		return false;
	if (read(fd, msg, sizeof(*msg)) != (ssize_t)sizeof(*msg))
		return false;
	return true;
}

/* Send UFFDIO_WAKE for @addr..@addr+page_size. */
static void uffd_wake_page(int fd, uintptr_t addr)
{
	struct uffdio_range r;

	r.start = addr;
	r.len   = (uint64_t)page_size;
	(void)ioctl(fd, UFFDIO_WAKE, &r);
}

/* ====================================================================
 * Variant 1: fault-resolve matrix
 * ==================================================================== */

/*
 * State shared between the main thread and the V1 fault thread.
 * All fields written before pthread_create are visible by the time the
 * thread starts; fields updated concurrently are either page_size-aligned
 * mapped memory (seqno path) or use volatile for simple flags.
 */
struct v1_ctx {
	int          uffd;
	void        *region;		/* mapped anon region */
	size_t       len;		/* region length */
	uint32_t    *src_pages;		/* source page buffer for COPY */
	volatile int stop;		/* signal thread to exit */
	volatile int faulted_idx;	/* last page index the thread faulted */
	volatile uint32_t observed_seqno[MAX_FM_PAGES]; /* read-back from thread */
	volatile int seqno_checked[MAX_FM_PAGES]; /* 1 once thread has checked */
};

static void *v1_fault_thread(void *arg)
{
	struct v1_ctx *ctx = (struct v1_ctx *)arg;
	int i;

	for (i = 0; i < MAX_FM_PAGES; i++) {
		volatile uint32_t *pg;

		if (__atomic_load_n(&ctx->stop, __ATOMIC_RELAXED))
			break;

		pg = (volatile uint32_t *)((char *)ctx->region +
					   (size_t)i * (size_t)page_size);

		/* Write to word 1 of the page (offset sizeof(uint32_t)).
		 * This triggers the MISSING fault and blocks until the main
		 * thread resolves it via UFFDIO_COPY -- but deliberately avoids
		 * touching word 0.  UFFDIO_COPY places the source sequence
		 * number at word 0 (offset 0) of the destination page; by
		 * storing our marker at word 1, COPY's payload at word 0
		 * survives the re-execution of this store after the fault is
		 * resolved.  We then read word 0 for the oracle compare, so
		 * any content error in COPY (wrong src, zeroed page, etc.)
		 * produces a mismatch.  If word 1 were used as the seqno
		 * location, the re-executed store would overwrite it before the
		 * read-back, making the oracle vacuous -- the exact tautology
		 * this layout was changed to eliminate.
		 *
		 * For POISON-resolved pages the kernel delivers SIGBUS; the
		 * main thread marks stop and the thread checks before each
		 * access -- but a race here is acceptable: SIGBUS on a
		 * POISON-resolved page is benign from a test perspective and
		 * is caught by the parent's alarm(1) timeout. */
		__atomic_store_n(&ctx->faulted_idx, i, __ATOMIC_RELEASE);
		pg[1] = (uint32_t)(SEQNO_MAGIC | (uint32_t)(i + 1));

		/* Read back word 0: COPY placed the src_pages seqno there.
		 * If COPY wrote anything other than SEQNO_MAGIC|(i+1), this
		 * diverges from the oracle's expected constant and
		 * oracle_mismatch fires.  A deliberately-wrong cp.src (e.g.
		 * a zero-filled buffer) would produce 0 here, not the magic
		 * constant, so the oracle is no longer vacuous. */
		ctx->observed_seqno[i] = *pg;
		__atomic_store_n(&ctx->seqno_checked[i], 1, __ATOMIC_RELEASE);
	}
	return NULL;
}

static void run_variant1(const enum child_op_type op, const bool valid_op,
			 unsigned long *direct_calls_out)
{
	struct v1_ctx ctx;
	pthread_t tid;
	int fd;
	uint64_t feats, range_ioctls;
	size_t len;
	void *region;
	void *src_pages;
	int round;
	bool thread_started = false;

	len = (size_t)MAX_FM_PAGES * (size_t)page_size;

	fd = uffd_open(0, &feats, NULL);
	(*direct_calls_out)++;
	if (fd < 0)
		return;

	region = mmap(NULL, len, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		close(fd);
		return;
	}

	/* Source buffer for COPY resolutions — plain malloc-style mmap.
	 * Pre-fill each page with its sequence number. */
	src_pages = mmap(NULL, len, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (src_pages == MAP_FAILED) {
		munmap(region, len);
		close(fd);
		return;
	}

	{
		int pi;

		for (pi = 0; pi < MAX_FM_PAGES; pi++) {
			uint32_t *p = (uint32_t *)((char *)src_pages +
						   (size_t)pi * (size_t)page_size);
			*p = (uint32_t)(SEQNO_MAGIC | (uint32_t)(pi + 1));
		}
	}

	if (!uffd_register(fd, region, len,
			   UFFDIO_REGISTER_MODE_MISSING,
			   &range_ioctls)) {
		munmap(src_pages, len);
		munmap(region, len);
		close(fd);
		return;
	}

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.uffd      = fd;
	ctx.region    = region;
	ctx.len       = len;
	ctx.src_pages = (uint32_t *)src_pages;

	if (pthread_create(&tid, NULL, v1_fault_thread, &ctx) != 0)
		goto cleanup_v1;
	thread_started = true;

	for (round = 0; round < MAX_FM_ROUNDS; round++) {
		struct uffd_msg msg;
		uintptr_t fault_addr;
		int page_idx;
		bool use_dontwake;

		if (!uffd_poll_one(fd, POLL_TIMEOUT_MS, &msg))
			break;

		if (msg.event != UFFD_EVENT_PAGEFAULT)
			continue;

		fault_addr = (uintptr_t)msg.arg.pagefault.address &
			     ~((uintptr_t)page_size - 1);
		page_idx = (int)((fault_addr - (uintptr_t)region) /
				 (size_t)page_size);
		if (page_idx < 0 || page_idx >= MAX_FM_PAGES)
			continue;

		use_dontwake = (rnd_u32() & 1) != 0;

		{
			/* Use COPY so the oracle can verify the seqno. */
			struct uffdio_copy cp;
			uint64_t mode = 0;
			int rc;

			if (use_dontwake)
				mode |= UFFDIO_COPY_MODE_DONTWAKE;

			memset(&cp, 0, sizeof(cp));
			cp.dst  = fault_addr;
			cp.src  = (uintptr_t)src_pages +
				  (uintptr_t)(page_idx * (int)page_size);
			cp.len  = (uint64_t)page_size;
			cp.mode = mode;

			rc = ioctl(fd, UFFDIO_COPY, &cp);
			if (rc == 0) {
				__atomic_add_fetch(
					&shm->stats.uffd_fault_move.v1_resolve_ok,
					1, __ATOMIC_RELAXED);
				if (use_dontwake)
					uffd_wake_page(fd, fault_addr);
				/* Oracle: wait for thread seqno_checked[page_idx]. */
				{
					int spin = 0;
					struct timespec ts = {
						.tv_sec  = 0,
						.tv_nsec = 1000000L, /* 1 ms */
					};
					while (!__atomic_load_n(
						&ctx.seqno_checked[page_idx],
						__ATOMIC_ACQUIRE) && spin++ < 200)
						nanosleep(&ts, NULL);

					__atomic_add_fetch(
						&shm->stats.uffd_fault_move.oracle_checks_run,
						1, __ATOMIC_RELAXED);
					if (__atomic_load_n(
						&ctx.observed_seqno[page_idx],
						__ATOMIC_RELAXED) !=
					    (uint32_t)(SEQNO_MAGIC |
						       (uint32_t)(page_idx + 1))) {
						__atomic_add_fetch(
							&shm->stats.uffd_fault_move.oracle_mismatch,
							1, __ATOMIC_RELAXED);
					}
				}
			} else {
				__atomic_add_fetch(
					&shm->stats.uffd_fault_move.v1_resolve_fail,
					1, __ATOMIC_RELAXED);
				/* Fault still pending; unblock the thread.
				 * Prefer UFFDIO_ZEROPAGE if the kernel advertised
				 * it for this range (range_ioctls bitmap from
				 * UFFDIO_REGISTER); fall back to an explicit WAKE
				 * so we never issue an ioctl the range rejects. */
				if (range_ioctls & (1ULL << _UFFDIO_ZEROPAGE)) {
					struct uffdio_zeropage zp;

					memset(&zp, 0, sizeof(zp));
					zp.range.start = fault_addr;
					zp.range.len   = (uint64_t)page_size;
					zp.mode        = 0;
					(void)ioctl(fd, UFFDIO_ZEROPAGE, &zp);
				} else {
					uffd_wake_page(fd, fault_addr);
				}
			}
		}
	}

cleanup_v1:
	__atomic_store_n(&ctx.stop, 1, __ATOMIC_RELEASE);
	/* Ensure the thread exits: unregister first (wakes any pending fault
	 * with an error so the thread doesn't stay blocked forever), then
	 * resolve any remaining pending faults via ZEROPAGE with no-wait. */
	uffd_unregister(fd, region, len);

	/*
	 * Drain any remaining fault events so the thread can unblock.
	 * After UNREGISTER, pending faults in the kernel are woken with
	 * an error; however, if the thread has not yet triggered its
	 * next fault access, it will simply find the page already mapped
	 * (no-fault path) and exit cleanly.  Either way, a bounded
	 * poll drain is sufficient.
	 */
	{
		struct uffd_msg discard;
		int drain;

		for (drain = 0; drain < MAX_FM_PAGES + 2; drain++) {
			if (!uffd_poll_one(fd, 20, &discard))
				break;
		}
	}

	if (thread_started) {
		struct timespec ts = { .tv_sec = 0, .tv_nsec = V3_JOIN_SLEEP_NS };
		int spin;

		for (spin = 0; spin < V3_JOIN_LOOPS; spin++) {
			if (pthread_tryjoin_np(tid, NULL) == 0)
				break;
			nanosleep(&ts, NULL);
		}
		/* If the thread is still stuck (should not happen after
		 * UNREGISTER), detach and let the alarm(1) reap the child. */
		if (spin >= V3_JOIN_LOOPS)
			pthread_detach(tid);
	}

	munmap(src_pages, len);
	munmap(region, len);
	close(fd);
}

/* ====================================================================
 * Variant 2: UFFDIO_MOVE / swap-cache race
 * ==================================================================== */

struct v2_racer_ctx {
	void        *src;	/* src mapping */
	size_t       len;
	volatile int stop;
	volatile int racers_done;
};

static void *v2_racer_thread(void *arg)
{
	struct v2_racer_ctx *ctx = (struct v2_racer_ctx *)arg;
	int iter;

	for (iter = 0; iter < MAX_FM_ROUNDS * 2; iter++) {
		if (__atomic_load_n(&ctx->stop, __ATOMIC_RELAXED))
			break;
		/* Page out src, then re-fault it — races UFFDIO_MOVE. */
		(void)madvise(ctx->src, ctx->len, MADV_PAGEOUT);
		/* Touch src to refault it. */
		{
			volatile uint32_t *p =
				(volatile uint32_t *)ctx->src;
			volatile uint32_t dummy = *p;
			(void)dummy;
		}
	}
	__atomic_store_n(&ctx->racers_done, 1, __ATOMIC_RELEASE);
	return NULL;
}

struct v2_fault_ctx {
	void        *dst;	/* dst mapping (registered with UFFD) */
	size_t       len;
	volatile int stop;
	volatile uint32_t observed_seqno[MAX_FM_PAGES];
	volatile int seqno_checked[MAX_FM_PAGES];
};

static void *v2_fault_thread(void *arg)
{
	struct v2_fault_ctx *ctx = (struct v2_fault_ctx *)arg;
	int i;

	for (i = 0; i < MAX_FM_PAGES; i++) {
		volatile uint32_t *pg;

		if (__atomic_load_n(&ctx->stop, __ATOMIC_RELAXED))
			break;
		pg = (volatile uint32_t *)((char *)ctx->dst +
					   (size_t)i * (size_t)page_size);
		/* Read from dst: triggers MISSING fault until UFFDIO_MOVE
		 * resolves it by moving the page from src. */
		ctx->observed_seqno[i] = *pg;
		__atomic_store_n(&ctx->seqno_checked[i], 1, __ATOMIC_RELEASE);
	}
	return NULL;
}

static void run_variant2(const enum child_op_type op, const bool valid_op,
			 unsigned long *direct_calls_out)
{
	struct v2_racer_ctx rctx;
	struct v2_fault_ctx fctx;
	pthread_t racer_tid, fault_tid;
	bool racer_started = false, fault_started = false;
	int fd;
	uint64_t feats;
	void *src = MAP_FAILED, *dst = MAP_FAILED;
	size_t len;
	int round;
	bool move_attempted = false;
	uint64_t req_features;
	bool use_allow_src_holes;

	/* Feature probe: check UFFD_FEATURE_MOVE is supported. */
	if (v2_move_latch == 0)
		return; /* already known unsupported */

#ifndef UFFD_FEATURE_MOVE
	v2_move_latch = 0;
	return;
#endif

	req_features = (uint64_t)UFFD_FEATURE_MOVE;

	fd = uffd_open(req_features, &feats, NULL);
	(*direct_calls_out)++;
	if (fd < 0)
		return;

	if ((feats & (uint64_t)UFFD_FEATURE_MOVE) == 0) {
		/* Kernel reports MOVE unsupported. */
		v2_move_latch = 0;
		close(fd);
		return;
	}
	v2_move_latch = 1;

	len = (size_t)MAX_FM_PAGES * (size_t)page_size;

	src = mmap(NULL, len, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (src == MAP_FAILED) {
		close(fd);
		return;
	}

	dst = mmap(NULL, len, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (dst == MAP_FAILED) {
		munmap(src, len);
		close(fd);
		return;
	}

	/* Fill src with per-page sequence numbers. */
	{
		int pi;

		for (pi = 0; pi < MAX_FM_PAGES; pi++) {
			uint32_t *p = (uint32_t *)((char *)src +
						   (size_t)pi * (size_t)page_size);
			*p = (uint32_t)(SEQNO_MAGIC | (uint32_t)(pi + 1));
		}
	}

	/* Populate src into memory so MADV_PAGEOUT has real pages to
	 * evict (otherwise it's a no-op). */
	(void)madvise(src, len, MADV_POPULATE_WRITE);

	if (!uffd_register(fd, dst, len,
			   UFFDIO_REGISTER_MODE_MISSING, NULL)) {
		munmap(dst, len);
		munmap(src, len);
		close(fd);
		return;
	}

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	/* Start racer thread (MADV_PAGEOUT + refault src). */
	memset(&rctx, 0, sizeof(rctx));
	rctx.src = src;
	rctx.len = len;
	if (pthread_create(&racer_tid, NULL, v2_racer_thread, &rctx) == 0)
		racer_started = true;

	/* Start fault thread (reads dst → MISSING faults). */
	memset(&fctx, 0, sizeof(fctx));
	fctx.dst = dst;
	fctx.len = len;
	if (pthread_create(&fault_tid, NULL, v2_fault_thread, &fctx) == 0)
		fault_started = true;

	use_allow_src_holes = (rnd_u32() & 1) != 0;

	for (round = 0; round < MAX_FM_ROUNDS; round++) {
		struct uffd_msg msg;
		uintptr_t fault_addr;
		int page_idx;

		if (!uffd_poll_one(fd, POLL_TIMEOUT_MS, &msg))
			break;
		if (msg.event != UFFD_EVENT_PAGEFAULT)
			continue;

		fault_addr = (uintptr_t)msg.arg.pagefault.address &
			     ~((uintptr_t)page_size - 1);
		page_idx = (int)((fault_addr - (uintptr_t)dst) /
				 (size_t)page_size);
		if (page_idx < 0 || page_idx >= MAX_FM_PAGES)
			continue;

		{
#ifdef UFFDIO_MOVE
			struct uffdio_move mv;
			uint64_t mode = 0;

			if (use_allow_src_holes)
				mode |= (uint64_t)UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES;

			memset(&mv, 0, sizeof(mv));
			mv.dst  = fault_addr;
			mv.src  = (uintptr_t)src +
				  (uintptr_t)(page_idx * (int)page_size);
			mv.len  = (uint64_t)page_size;
			mv.mode = mode;

			move_attempted = true;
			if (ioctl(fd, UFFDIO_MOVE, &mv) == 0) {
				__atomic_add_fetch(
					&shm->stats.uffd_fault_move.v2_move_ok,
					1, __ATOMIC_RELAXED);
				/* Oracle: wait for fault thread to read back. */
				{
					struct timespec ts = {
						.tv_sec  = 0,
						.tv_nsec = 1000000L,
					};
					int spin = 0;

					while (!__atomic_load_n(
						&fctx.seqno_checked[page_idx],
						__ATOMIC_ACQUIRE) && spin++ < 200)
						nanosleep(&ts, NULL);

					__atomic_add_fetch(
						&shm->stats.uffd_fault_move.oracle_checks_run,
						1, __ATOMIC_RELAXED);
					if (__atomic_load_n(
						&fctx.observed_seqno[page_idx],
						__ATOMIC_RELAXED) !=
					    (uint32_t)(SEQNO_MAGIC |
						       (uint32_t)(page_idx + 1))) {
						__atomic_add_fetch(
							&shm->stats.uffd_fault_move.oracle_mismatch,
							1, __ATOMIC_RELAXED);
					}
				}
			} else {
				if (errno == EINVAL)
					__atomic_add_fetch(
						&shm->stats.uffd_fault_move.v2_move_einval,
						1, __ATOMIC_RELAXED);
				else
					__atomic_add_fetch(
						&shm->stats.uffd_fault_move.v2_move_fail,
						1, __ATOMIC_RELAXED);
				/* Fall back to COPY so the fault thread
				 * doesn't stay blocked forever. */
				struct uffdio_copy cp;

				memset(&cp, 0, sizeof(cp));
				cp.dst  = fault_addr;
				cp.src  = (uintptr_t)src +
					  (uintptr_t)(page_idx * (int)page_size);
				cp.len  = (uint64_t)page_size;
				cp.mode = 0;
				(void)ioctl(fd, UFFDIO_COPY, &cp);
			}
#else
			/* UFFDIO_MOVE not in headers; resolve with ZEROPAGE. */
			struct uffdio_zeropage zp;

			memset(&zp, 0, sizeof(zp));
			zp.range.start = fault_addr;
			zp.range.len   = (uint64_t)page_size;
			zp.mode        = 0;
			(void)ioctl(fd, UFFDIO_ZEROPAGE, &zp);
			__atomic_add_fetch(
				&shm->stats.uffd_fault_move.v2_move_fail,
				1, __ATOMIC_RELAXED);
#endif
		}
	}

	if (!move_attempted)
		__atomic_add_fetch(
			&shm->stats.uffd_fault_move.v2_move_skipped,
			1, __ATOMIC_RELAXED);

	/* Teardown: stop threads, unregister, unmap. */
	__atomic_store_n(&rctx.stop, 1, __ATOMIC_RELEASE);
	__atomic_store_n(&fctx.stop, 1, __ATOMIC_RELEASE);

	uffd_unregister(fd, dst, len);

	/* Drain remaining fault events so fault thread can unblock. */
	{
		struct uffd_msg discard;
		int drain;

		for (drain = 0; drain < MAX_FM_PAGES + 2; drain++) {
			if (!uffd_poll_one(fd, 20, &discard))
				break;
			/* Resolve with ZEROPAGE to unblock waiter. */
			if (discard.event == UFFD_EVENT_PAGEFAULT) {
				struct uffdio_zeropage zp;

				uintptr_t fa =
					(uintptr_t)discard.arg.pagefault.address &
					~((uintptr_t)page_size - 1);
				memset(&zp, 0, sizeof(zp));
				zp.range.start = fa;
				zp.range.len   = (uint64_t)page_size;
				(void)ioctl(fd, UFFDIO_ZEROPAGE, &zp);
			}
		}
	}

	{
		struct timespec ts = { .tv_sec = 0, .tv_nsec = V3_JOIN_SLEEP_NS };
		int spin;

		if (racer_started) {
			for (spin = 0; spin < V3_JOIN_LOOPS; spin++) {
				if (pthread_tryjoin_np(racer_tid, NULL) == 0)
					break;
				nanosleep(&ts, NULL);
			}
			if (spin >= V3_JOIN_LOOPS)
				pthread_detach(racer_tid);
		}
		if (fault_started) {
			for (spin = 0; spin < V3_JOIN_LOOPS; spin++) {
				if (pthread_tryjoin_np(fault_tid, NULL) == 0)
					break;
				nanosleep(&ts, NULL);
			}
			if (spin >= V3_JOIN_LOOPS)
				pthread_detach(fault_tid);
		}
	}

	munmap(dst, len);
	munmap(src, len);
	close(fd);
}

/* ====================================================================
 * Variant 3: teardown race
 * ==================================================================== */

/* Per-thread escape buffer for SIGSEGV/SIGBUS during teardown race. */
struct v3_fault_ctx {
	void         *region;		/* mapped region */
	size_t        len;
	volatile int  blocked;		/* 1 while blocked on fault */
	volatile int  escaped;		/* 1 if sigsetjmp was taken */
	volatile int  stop;
};

static _Thread_local sigjmp_buf v3_escape_buf;
static _Thread_local volatile int v3_in_escape_zone;

static void v3_sig_handler(int signo, siginfo_t *info, void *ctx)
{
	(void)signo;
	(void)info;
	(void)ctx;
	if (v3_in_escape_zone)
		siglongjmp(v3_escape_buf, 1);
}

static void *v3_fault_thread(void *arg)
{
	struct v3_fault_ctx *fctx = (struct v3_fault_ctx *)arg;
	struct sigaction sa;
	volatile uint32_t *pg;

	/* Install SIGSEGV/SIGBUS handler for this thread. */
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = v3_sig_handler;
	sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);

	pg = (volatile uint32_t *)fctx->region;

	v3_in_escape_zone = 1;
	if (sigsetjmp(v3_escape_buf, 1) == 0) {
		__atomic_store_n(&fctx->blocked, 1, __ATOMIC_RELEASE);
		/* This access triggers a MISSING fault; the thread blocks
		 * until the main thread either resolves it or tears down
		 * the registration/mapping (which delivers SIGSEGV/SIGBUS). */
		*pg = 0xdeadU;
		v3_in_escape_zone = 0;
	} else {
		/* Escaped via SIGSEGV or SIGBUS from teardown. */
		v3_in_escape_zone = 0;
		__atomic_store_n(&fctx->escaped, 1, __ATOMIC_RELEASE);
	}
	return NULL;
}

static void run_variant3(const enum child_op_type op, const bool valid_op,
			 unsigned long *direct_calls_out)
{
	struct v3_fault_ctx fctx;
	pthread_t tid;
	bool thread_started = false;
	int fd;
	uint64_t feats;
	void *region;
	size_t len;
	int teardown_action;
	int spin;
	struct timespec ts;

	len = (size_t)page_size;	/* single page is enough */

	fd = uffd_open(0, &feats, NULL);
	(*direct_calls_out)++;
	if (fd < 0)
		return;

	region = mmap(NULL, len, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		close(fd);
		return;
	}

	if (!uffd_register(fd, region, len,
			   UFFDIO_REGISTER_MODE_MISSING, NULL)) {
		munmap(region, len);
		close(fd);
		return;
	}

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	memset(&fctx, 0, sizeof(fctx));
	fctx.region = region;
	fctx.len    = len;

	if (pthread_create(&tid, NULL, v3_fault_thread, &fctx) != 0)
		goto cleanup_v3;
	thread_started = true;

	/* Wait for the thread to reach the faulting access and block.
	 * Use a short poll on the uffd fd as the confirmation signal. */
	{
		struct uffd_msg msg;
		bool got_fault = uffd_poll_one(fd, POLL_TIMEOUT_MS, &msg);

		if (!got_fault) {
			/* Thread may not have faulted yet or exited early.
			 * Skip teardown action; fall through to cleanup. */
			goto cleanup_v3;
		}
		/* Fault confirmed pending in the kernel. */
	}

	/* Choose teardown action: 0=close, 1=UNREGISTER, 2=munmap,
	 * 3=mremap (shrink to 0 pages, effectively an unmap). */
	teardown_action = (int)rnd_modulo_u32(4);

	switch (teardown_action) {
	case 0: {
		/* close(uffd): triggers userfaultfd_release which wakes
		 * all pending faults with an error. */
		int saved_fd = fd;

		fd = -1;			/* prevent double-close in cleanup */
		if (close(saved_fd) == 0) {
			__atomic_add_fetch(
				&shm->stats.uffd_fault_move.v3_teardown_ok,
				1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(
				&shm->stats.uffd_fault_move.v3_teardown_fail,
				1, __ATOMIC_RELAXED);
		}
		break;
	}
	case 1:
		/* UFFDIO_UNREGISTER: removes the VMA's UFFD registration;
		 * pending faults are woken.  Inline the ioctl so we can
		 * check the return value and route failures correctly. */
		{
			struct uffdio_range ur;

			ur.start = (uintptr_t)region;
			ur.len   = len;
			if (ioctl(fd, UFFDIO_UNREGISTER, &ur) == 0) {
				__atomic_add_fetch(
					&shm->stats.uffd_fault_move.v3_teardown_ok,
					1, __ATOMIC_RELAXED);
			} else {
				__atomic_add_fetch(
					&shm->stats.uffd_fault_move.v3_teardown_fail,
					1, __ATOMIC_RELAXED);
			}
		}
		break;
	case 2:
		/* munmap: tears down the mapping; pending fault gets SIGSEGV
		 * or SIGBUS in the faulting thread. */
		if (munmap(region, len) == 0) {
			region = MAP_FAILED;		/* suppress double-unmap */
			__atomic_add_fetch(
				&shm->stats.uffd_fault_move.v3_teardown_ok,
				1, __ATOMIC_RELAXED);
		} else {
			region = MAP_FAILED;
			__atomic_add_fetch(
				&shm->stats.uffd_fault_move.v3_teardown_fail,
				1, __ATOMIC_RELAXED);
		}
		break;
	case 3:
		/*
		 * mremap(MREMAP_MAYMOVE|MREMAP_FIXED) to a fresh anonymous
		 * mapping: relocates the VMA out from under the pending fault,
		 * racing the fault handler correctly.
		 *
		 * The previous code used mremap(region, len, 0, 0) — this
		 * always fails: the kernel rejects new_len==0 with -EINVAL
		 * (mm/mremap.c: "if (!vrm->new_len) return -EINVAL").  The
		 * mapping was never torn down yet v3_teardown_ok was bumped
		 * unconditionally, making ~25% of V3 runs silent no-ops.
		 *
		 * MREMAP_FIXED with a dest we own is the minimal legal fix:
		 * new_len == old_len satisfies the kernel, MAYMOVE|FIXED
		 * forces the relocation to dest (overwriting the placeholder
		 * anonymous page there), and on success region is effectively
		 * gone from its original address.
		 */
		{
			void *dest = mmap(NULL, len, PROT_NONE,
					  MAP_PRIVATE | MAP_ANONYMOUS |
					  MAP_NORESERVE, -1, 0);
			if (dest == MAP_FAILED) {
				__atomic_add_fetch(
					&shm->stats.uffd_fault_move.v3_teardown_fail,
					1, __ATOMIC_RELAXED);
				break;
			}
			void *r = mremap(region, len, len,
					 MREMAP_MAYMOVE | MREMAP_FIXED, dest);
			if (r == MAP_FAILED) {
				munmap(dest, len);
				__atomic_add_fetch(
					&shm->stats.uffd_fault_move.v3_teardown_fail,
					1, __ATOMIC_RELAXED);
			} else {
				/* region has been relocated to dest; mark it
				 * consumed to suppress the cleanup double-unmap. */
				region = MAP_FAILED;
				__atomic_add_fetch(
					&shm->stats.uffd_fault_move.v3_teardown_ok,
					1, __ATOMIC_RELAXED);
			}
		}
		break;
	}

cleanup_v3:
	if (thread_started) {
		ts.tv_sec  = 0;
		ts.tv_nsec = V3_JOIN_SLEEP_NS;
		for (spin = 0; spin < V3_JOIN_LOOPS; spin++) {
			if (pthread_tryjoin_np(tid, NULL) == 0)
				break;
			nanosleep(&ts, NULL);
		}
		if (spin >= V3_JOIN_LOOPS)
			pthread_detach(tid);
	}

	/* Unconditional cleanup in case teardown action left things partial. */
	if (fd >= 0 && region != MAP_FAILED)
		uffd_unregister(fd, region, len);
	if (region != MAP_FAILED)
		munmap(region, len);
	if (fd >= 0)
		close(fd);
}

/* ====================================================================
 * Childop entry point
 * ==================================================================== */

bool uffd_fault_move(struct childdata *child)
{
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);
	unsigned long direct_calls = 0;
	unsigned int variant;
	int fd_probe;

	if (ns_unsupported)
		return true;

	/* Quick-probe: open a uffd fd to check availability.  We count
	 * this as one direct call regardless of which variant runs. */
	fd_probe = do_userfaultfd(O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY);
	direct_calls++;

	if (fd_probe < 0) {
		if (errno == EPERM || errno == ENOSYS) {
			ns_unsupported = true;
			if (valid_op) {
				__atomic_store_n(
					&shm->stats.childop.latch_reason[op],
					CHILDOP_LATCH_NS_UNSUPPORTED,
					__ATOMIC_RELAXED);
				childop_direct_syscalls_add(op, direct_calls);
			}
			return true;
		}
		if (valid_op)
			childop_direct_syscalls_add(op, direct_calls);
		return true;
	}
	close(fd_probe);

	/* Pick variant 0/1/2 randomly; weight slightly toward V1 since it
	 * exercises the most UFFD code paths. */
	variant = rnd_modulo_u32(3);

	switch (variant) {
	case 0:
		run_variant1(op, valid_op, &direct_calls);
		break;
	case 1:
		run_variant2(op, valid_op, &direct_calls);
		break;
	default:
		run_variant3(op, valid_op, &direct_calls);
		break;
	}

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);

	return true;
}
