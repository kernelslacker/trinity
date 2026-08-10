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
 *   Register an anonymous VMA MISSING|WP (WP registration falls back to
 *   MISSING-only on kernels that reject it).  A fault thread accesses one
 *   page at a time, blocking inside the kernel until the main thread
 *   resolves the fault.  Resolution rotates per page index (mod 4),
 *   gated on the range_ioctls bitmap returned by UFFDIO_REGISTER:
 *     page%4==0  UFFDIO_COPY (always available; oracle verifies seqno)
 *     page%4==1  UFFDIO_ZEROPAGE if gated, else COPY fallback
 *     page%4==2  UFFDIO_POISON if gated; subsequent access delivers
 *                SIGBUS (caught by fault thread via sigsetjmp)
 *     page%4==3  UFFDIO_COPY|WP if WP is registered and gated, else
 *                COPY fallback; write-protecting the resolved page
 *                causes the thread's re-executed write to generate a
 *                second WP fault, which is resolved with
 *                UFFDIO_WRITEPROTECT (unprotect).
 *   DONTWAKE is exercised on COPY, ZEROPAGE and COPY|WP resolutions;
 *   the fault thread's progress is measured before the explicit WAKE
 *   to distinguish "thread stayed blocked" from "kernel woke early".
 *   Stat fields: v1_wp_faults_resolved, v1_poison_faults_resolved,
 *   v1_dontwake_still_blocked, v1_dontwake_woke_early.
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
 *   - All variant fault/racer threads are joined with a bounded busy-poll
 *     (pthread_tryjoin_np).  On timeout the mapping is deliberately leaked
 *     (munmap/close skipped) so the child-process exit reclaims it — safer
 *     than pthread_detach followed by munmap under a live thread.
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
#define V3_JOIN_LOOPS		20	/* 20 × 5 ms = 100 ms, well inside alarm(1) */
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
	/* POISON resolution: main sets poison_resolved[i]=1 before waking;
	 * fault thread sees SIGBUS on the re-executed access and escapes via
	 * sigsetjmp; sigbus_escaped[i] is set inside the handler to confirm
	 * the SIGBUS was from a POISON page rather than a stray signal. */
	volatile int poison_resolved[MAX_FM_PAGES];
	volatile int sigbus_escaped[MAX_FM_PAGES];
	/* Saved signal dispositions — installed by fault thread, restored
	 * by run_variant1() after join so the process-wide state is clean. */
	struct sigaction old_sa_segv;
	struct sigaction old_sa_bus;
};

/* Per-thread escape state for SIGBUS (POISON) in the v1 fault thread. */
static _Thread_local sigjmp_buf v1_escape_buf;
static _Thread_local volatile int v1_in_escape_zone;
static _Thread_local volatile int v1_escape_page_idx;
static _Thread_local struct v1_ctx *v1_thread_ctx;

static void v1_sigbus_handler(int signo, siginfo_t *info, void *uctx)
{
	(void)info;
	(void)uctx;
	if (v1_in_escape_zone) {
		siglongjmp(v1_escape_buf, 1);
	} else {
		/* SIGBUS outside escape zone — not ours; reset and re-raise. */
		raise(signo);
	}
}

static void *v1_fault_thread(void *arg)
{
	struct v1_ctx *ctx = (struct v1_ctx *)arg;
	struct sigaction sa;
	int i;

	/* Install SIGBUS handler for POISON-resolved pages.  sigaction() is
	 * process-wide; save old dispositions in ctx so run_variant1() can
	 * restore them after the thread is joined. */
	v1_thread_ctx = ctx;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = v1_sigbus_handler;
	sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGBUS, &sa, &ctx->old_sa_bus);
	sigaction(SIGSEGV, &sa, &ctx->old_sa_segv);

	for (i = 0; i < MAX_FM_PAGES; i++) {
		volatile uint32_t *pg;

		if (__atomic_load_n(&ctx->stop, __ATOMIC_RELAXED))
			break;

		pg = (volatile uint32_t *)((char *)ctx->region +
					   (size_t)i * (size_t)page_size);

		/* Arm sigsetjmp escape zone around the fault-triggering access.
		 * If this page is POISON-resolved, the re-executed write below
		 * delivers SIGBUS; v1_sigbus_handler() siglongjmp()s back here
		 * with value 1 so we record the escape and continue to the
		 * next page rather than spinning or crashing. */
		v1_escape_page_idx = i;
		v1_in_escape_zone = 1;
		if (sigsetjmp(v1_escape_buf, 1) != 0) {
			/* Escaped SIGBUS from a POISON-resolved page. */
			v1_in_escape_zone = 0;
			__atomic_store_n(&ctx->sigbus_escaped[i], 1,
					 __ATOMIC_RELEASE);
			/* Re-install handler: SA_RESETHAND cleared it. */
			sigaction(SIGBUS,  &sa, NULL);
			sigaction(SIGSEGV, &sa, NULL);
			continue;
		}

		/* Write to word 1 of the page (offset sizeof(uint32_t)).
		 * This triggers the MISSING fault and blocks until the main
		 * thread resolves it.  Deliberately avoids word 0 so that
		 * UFFDIO_COPY's payload at word 0 survives the re-execution
		 * of this store.  The oracle reads word 0; if COPY wrote
		 * anything other than SEQNO_MAGIC|(i+1), oracle_mismatch
		 * fires — the oracle is no longer vacuous.
		 *
		 * For COPY|WP-resolved pages (WP arm), this re-executed write
		 * triggers a WP fault; the main thread handles it separately
		 * with UFFDIO_WRITEPROTECT (unprotect) before this write
		 * finally completes. */
		__atomic_store_n(&ctx->faulted_idx, i, __ATOMIC_RELEASE);
		/* Keep the escape zone open across both the fault-inducing write
		 * (pg[1]) and the subsequent read-back (*pg): a SIGBUS/SIGSEGV on
		 * either must be caught by v1_sigbus_handler via sigsetjmp, not
		 * treated as fatal. */
		pg[1] = (uint32_t)(SEQNO_MAGIC | (uint32_t)(i + 1));

		/* Read back word 0: COPY placed the src_pages seqno there. */
		ctx->observed_seqno[i] = *pg;
		__atomic_store_n(&ctx->seqno_checked[i], 1, __ATOMIC_RELEASE);
		v1_in_escape_zone = 0;
	}
	return NULL;
}

/*
 * After COPY+DONTWAKE, spin briefly to check whether the fault thread
 * unblocked before we issue an explicit WAKE.  A well-behaved kernel
 * should leave the thread sleeping; if seqno_checked[idx] is already
 * set the kernel woke the thread early (woke_early counter).
 * DONTWAKE_SPIN_MS * DONTWAKE_SPIN_ITERS sets the measurement window
 * to ~5 ms — enough to detect an inadvertent wake-up without consuming
 * significant wall time.
 */
#define DONTWAKE_SPIN_ITERS	5
#define DONTWAKE_SPIN_NS	1000000L	/* 1 ms per spin */

static void v1_measure_dontwake(const struct v1_ctx *ctx, int page_idx,
				int fd, uintptr_t fault_addr)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = DONTWAKE_SPIN_NS };
	int s;

	for (s = 0; s < DONTWAKE_SPIN_ITERS; s++) {
		if (__atomic_load_n(&ctx->seqno_checked[page_idx],
				    __ATOMIC_ACQUIRE))
			break;
		nanosleep(&ts, NULL);
	}

	if (__atomic_load_n(&ctx->seqno_checked[page_idx], __ATOMIC_ACQUIRE)) {
		/* Thread unblocked before explicit WAKE. */
		__atomic_add_fetch(
			&shm->stats.uffd_fault_move.v1_dontwake_woke_early,
			1, __ATOMIC_RELAXED);
	} else {
		/* Thread correctly stayed blocked. */
		__atomic_add_fetch(
			&shm->stats.uffd_fault_move.v1_dontwake_still_blocked,
			1, __ATOMIC_RELAXED);
	}
	/* Now explicitly wake the thread. */
	uffd_wake_page(fd, fault_addr);
}

static void run_variant1(const enum child_op_type op, const bool valid_op,
			 unsigned long *direct_calls_out)
{
	/* Static storage so a worker that outlives the frame (leak path) can
	 * still dereference its ctx pointer without hitting a dead stack frame. */
	static struct v1_ctx ctx;
	pthread_t tid;
	int fd;
	uint64_t feats;
	uint64_t range_ioctls;
	size_t len;
	void *region;
	void *src_pages;
	int round;
	int missing_handled;
	bool thread_started = false;
	bool wp_registered;
	bool wp_ioctl_avail;
	bool poison_avail;
	bool zeropage_avail;

	len = (size_t)MAX_FM_PAGES * (size_t)page_size;

	fd = uffd_open(0, &feats, NULL);
	(*direct_calls_out)++;
	if (fd < 0)
		return;
	(void)feats;	/* negotiated for future feature gates; unused in V1 */

	region = mmap(NULL, len, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		close(fd);
		return;
	}

	/* Source buffer for COPY resolutions — plain malloc-style mmap.
	 * Pre-fill each page with its sequence number at word 0 (offset 0);
	 * the fault thread writes its marker to word 1, so COPY's payload
	 * at word 0 is never overwritten and the oracle is non-vacuous. */
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

	/*
	 * Attempt MISSING|WP registration.  WP registration allows the
	 * UFFDIO_COPY_MODE_WP arm to write-protect a resolved page so
	 * that the thread's re-executed write triggers a WP fault, which
	 * we then unprotect with UFFDIO_WRITEPROTECT.  Fall back to
	 * MISSING-only on kernels that reject WP for anon VMAs.
	 */
	wp_registered = uffd_register(fd, region, len,
				      UFFDIO_REGISTER_MODE_MISSING |
				      UFFDIO_REGISTER_MODE_WP,
				      &range_ioctls);
	if (!wp_registered) {
		if (!uffd_register(fd, region, len,
				   UFFDIO_REGISTER_MODE_MISSING,
				   &range_ioctls)) {
			munmap(src_pages, len);
			munmap(region, len);
			close(fd);
			return;
		}
	}

	/* Gate each resolution arm on the range_ioctls bitmap returned by
	 * UFFDIO_REGISTER: the kernel only advertises ioctls that are
	 * actually legal for the registered range, so we never issue a
	 * resolution that the kernel will reject with -EINVAL. */
	wp_ioctl_avail  = wp_registered &&
			  (range_ioctls & (1ULL << _UFFDIO_WRITEPROTECT)) != 0;
	poison_avail	= (range_ioctls & (1ULL << _UFFDIO_POISON)) != 0;
	zeropage_avail	= (range_ioctls & (1ULL << _UFFDIO_ZEROPAGE)) != 0;

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

	/*
	 * Main resolve loop.  Each iteration handles one fault event.
	 * WP faults (flag UFFD_PAGEFAULT_FLAG_WP) come in addition to
	 * MISSING faults when the COPY|WP arm is used, so we run up to
	 * MAX_FM_ROUNDS * 2 iterations to accommodate both, stopping once
	 * all MAX_FM_PAGES MISSING faults have been resolved.
	 *
	 * Resolution is chosen by (page_idx % 4) for MISSING faults:
	 *   0: UFFDIO_COPY (always available; oracle check)
	 *   1: UFFDIO_ZEROPAGE if gated, else COPY fallback
	 *   2: UFFDIO_POISON if gated, else COPY fallback
	 *   3: UFFDIO_COPY|WP if WP gated, else COPY fallback; causes a
	 *      follow-up WP fault on the same page
	 */
	missing_handled = 0;
	for (round = 0;
	     round < MAX_FM_ROUNDS * 2 && missing_handled < MAX_FM_PAGES;
	     round++) {
		struct uffd_msg msg;
		uintptr_t fault_addr;
		int page_idx;
		bool is_wp_fault;

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

		is_wp_fault = (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) != 0;

		if (is_wp_fault) {
			/*
			 * WP fault: thread's re-executed write hit a
			 * write-protected page (set by the COPY|WP arm).
			 * Unprotect the page so the write can complete.
			 */
			struct uffdio_writeprotect wp;

			memset(&wp, 0, sizeof(wp));
			wp.range.start = fault_addr;
			wp.range.len   = (uint64_t)page_size;
			wp.mode        = 0;	/* MODE_WP=0 ⇒ unprotect */
			if (ioctl(fd, UFFDIO_WRITEPROTECT, &wp) == 0) {
				__atomic_add_fetch(
					&shm->stats.uffd_fault_move.v1_wp_faults_resolved,
					1, __ATOMIC_RELAXED);
			} else {
				/* Unprotect failed; unblock thread with WAKE. */
				uffd_wake_page(fd, fault_addr);
			}
			continue;
		}

		/* MISSING fault — choose resolution by page_idx % 4. */
		missing_handled++;

		switch (page_idx % 4) {
		case 0: {
			/*
			 * UFFDIO_COPY: resolve with seqno content so the
			 * oracle can verify word 0.  Use DONTWAKE randomly
			 * and measure whether the thread stayed blocked.
			 */
			struct uffdio_copy cp;
			bool use_dontwake = (rnd_u32() & 1) != 0;
			uint64_t cmode = use_dontwake ? UFFDIO_COPY_MODE_DONTWAKE : 0;

			memset(&cp, 0, sizeof(cp));
			cp.dst  = fault_addr;
			cp.src  = (uintptr_t)src_pages +
				  (uintptr_t)(page_idx * (int)page_size);
			cp.len  = (uint64_t)page_size;
			cp.mode = cmode;
			if (ioctl(fd, UFFDIO_COPY, &cp) == 0) {
				__atomic_add_fetch(
					&shm->stats.uffd_fault_move.v1_resolve_ok,
					1, __ATOMIC_RELAXED);
				if (use_dontwake)
					v1_measure_dontwake(&ctx, page_idx,
							    fd, fault_addr);
				/* Oracle: wait for thread to read back word 0. */
				{
					struct timespec ts = { 0, 1000000L };
					int spin = 0;

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
				uffd_wake_page(fd, fault_addr);
			}
			break;
		}
		case 1: {
			/*
			 * UFFDIO_ZEROPAGE: zero-fills the page; no oracle
			 * (zeroed content is expected, not seqno).  Fall
			 * back to COPY if ZEROPAGE is not in range_ioctls.
			 * Apply DONTWAKE randomly and measure it.
			 */
			if (zeropage_avail) {
				struct uffdio_zeropage zp;
				bool use_dontwake = (rnd_u32() & 1) != 0;
				uint64_t zmode = use_dontwake ?
					UFFDIO_ZEROPAGE_MODE_DONTWAKE : 0;

				memset(&zp, 0, sizeof(zp));
				zp.range.start = fault_addr;
				zp.range.len   = (uint64_t)page_size;
				zp.mode        = zmode;
				if (ioctl(fd, UFFDIO_ZEROPAGE, &zp) == 0) {
					__atomic_add_fetch(
						&shm->stats.uffd_fault_move.v1_resolve_ok,
						1, __ATOMIC_RELAXED);
					if (use_dontwake)
						v1_measure_dontwake(&ctx, page_idx,
								    fd, fault_addr);
				} else {
					__atomic_add_fetch(
						&shm->stats.uffd_fault_move.v1_resolve_fail,
						1, __ATOMIC_RELAXED);
					uffd_wake_page(fd, fault_addr);
				}
			} else {
				/* ZEROPAGE not available: use COPY as fallback. */
				struct uffdio_copy cp;

				memset(&cp, 0, sizeof(cp));
				cp.dst  = fault_addr;
				cp.src  = (uintptr_t)src_pages +
					  (uintptr_t)(page_idx * (int)page_size);
				cp.len  = (uint64_t)page_size;
				cp.mode = 0;
				if (ioctl(fd, UFFDIO_COPY, &cp) == 0)
					__atomic_add_fetch(
						&shm->stats.uffd_fault_move.v1_resolve_ok,
						1, __ATOMIC_RELAXED);
				else {
					__atomic_add_fetch(
						&shm->stats.uffd_fault_move.v1_resolve_fail,
						1, __ATOMIC_RELAXED);
					uffd_wake_page(fd, fault_addr);
				}
			}
			break;
		}
		case 2: {
			/*
			 * UFFDIO_POISON: marks the page as poisoned; the
			 * thread's re-executed write delivers SIGBUS, which
			 * v1_fault_thread catches via sigsetjmp and records
			 * as sigbus_escaped[page_idx].  Set poison_resolved
			 * in ctx before issuing the ioctl so the thread
			 * knows an expected SIGBUS is coming.
			 * Fall back to COPY if POISON is not in range_ioctls.
			 */
			if (poison_avail) {
				struct uffdio_poison pp;

				__atomic_store_n(&ctx.poison_resolved[page_idx],
						 1, __ATOMIC_RELEASE);
				memset(&pp, 0, sizeof(pp));
				pp.range.start = fault_addr;
				pp.range.len   = (uint64_t)page_size;
				pp.mode        = 0;
				if (ioctl(fd, UFFDIO_POISON, &pp) == 0) {
					__atomic_add_fetch(
						&shm->stats.uffd_fault_move.v1_resolve_ok,
						1, __ATOMIC_RELAXED);
					__atomic_add_fetch(
						&shm->stats.uffd_fault_move.v1_poison_faults_resolved,
						1, __ATOMIC_RELAXED);
				} else {
					/* POISON failed; clear flag and wake. */
					__atomic_store_n(
						&ctx.poison_resolved[page_idx],
						0, __ATOMIC_RELEASE);
					__atomic_add_fetch(
						&shm->stats.uffd_fault_move.v1_resolve_fail,
						1, __ATOMIC_RELAXED);
					uffd_wake_page(fd, fault_addr);
				}
			} else {
				/* POISON not available: use COPY as fallback. */
				struct uffdio_copy cp;

				memset(&cp, 0, sizeof(cp));
				cp.dst  = fault_addr;
				cp.src  = (uintptr_t)src_pages +
					  (uintptr_t)(page_idx * (int)page_size);
				cp.len  = (uint64_t)page_size;
				cp.mode = 0;
				if (ioctl(fd, UFFDIO_COPY, &cp) == 0)
					__atomic_add_fetch(
						&shm->stats.uffd_fault_move.v1_resolve_ok,
						1, __ATOMIC_RELAXED);
				else {
					__atomic_add_fetch(
						&shm->stats.uffd_fault_move.v1_resolve_fail,
						1, __ATOMIC_RELAXED);
					uffd_wake_page(fd, fault_addr);
				}
			}
			break;
		}
		default: {
			/*
			 * UFFDIO_COPY|WP: fill the page AND write-protect it.
			 * After this resolves the MISSING fault, the thread's
			 * re-executed write triggers a WP fault on the same
			 * page, handled above in the is_wp_fault branch.
			 * DONTWAKE is always used here to decouple MISSING
			 * resolution from the WAKE and to demonstrate that the
			 * thread stays blocked until the explicit WAKE even
			 * though the MISSING fault is resolved.
			 * Fall back to plain COPY if WP is not gated.
			 */
			struct uffdio_copy cp;
			uint64_t cmode;

			cmode = wp_ioctl_avail ?
				(UFFDIO_COPY_MODE_WP | UFFDIO_COPY_MODE_DONTWAKE) :
				0;

			memset(&cp, 0, sizeof(cp));
			cp.dst  = fault_addr;
			cp.src  = (uintptr_t)src_pages +
				  (uintptr_t)(page_idx * (int)page_size);
			cp.len  = (uint64_t)page_size;
			cp.mode = cmode;
			if (ioctl(fd, UFFDIO_COPY, &cp) == 0) {
				__atomic_add_fetch(
					&shm->stats.uffd_fault_move.v1_resolve_ok,
					1, __ATOMIC_RELAXED);
				if (wp_ioctl_avail) {
					/* DONTWAKE was set; measure before WAKE. */
					v1_measure_dontwake(&ctx, page_idx,
							    fd, fault_addr);
					/* After WAKE, thread re-executes write →
					 * WP fault → handled in is_wp_fault branch
					 * on the next loop iteration. */
				}
				/* Also run oracle (seqno is in word 0 from COPY). */
				{
					struct timespec ts = { 0, 1000000L };
					int spin = 0;

					while (!__atomic_load_n(
						&ctx.seqno_checked[page_idx],
						__ATOMIC_ACQUIRE) && spin++ < 200)
						nanosleep(&ts, NULL);

					if (__atomic_load_n(
						&ctx.seqno_checked[page_idx],
						__ATOMIC_ACQUIRE)) {
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
				}
			} else {
				__atomic_add_fetch(
					&shm->stats.uffd_fault_move.v1_resolve_fail,
					1, __ATOMIC_RELAXED);
				uffd_wake_page(fd, fault_addr);
			}
			break;
		}
		} /* switch */
	}

cleanup_v1:
	__atomic_store_n(&ctx.stop, 1, __ATOMIC_RELEASE);
	/* Unregister wakes any pending fault with an error, allowing the
	 * fault thread to unblock regardless of which page it is on. */
	uffd_unregister(fd, region, len);
	/* Belt-and-suspenders: WAKE the whole registered range so any fault
	 * still queued in the kernel is kicked out before we join. */
	{
		struct uffdio_range wr;

		wr.start = (uintptr_t)region;
		wr.len   = (uint64_t)len;
		(void)ioctl(fd, UFFDIO_WAKE, &wr);
	}

	/* Drain remaining fault events (bounded). */
	{
		struct uffd_msg discard;
		int drain;

		for (drain = 0; drain < MAX_FM_PAGES + 4; drain++) {
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
		if (spin >= V3_JOIN_LOOPS)
			return; /* worker still live: leak mappings, skip munmap */
		/* Restore signal dispositions installed by v1_fault_thread.
		 * sigaction() is process-wide; must be undone here so the next
		 * childop invocation sees the expected disposition.
		 * ctx is static storage so old_sa_* are always readable.
		 * Must come AFTER the leak-path check above: on the leak path
		 * the worker is still live and its sigsetjmp escape depends on
		 * the handler remaining installed. */
		sigaction(SIGBUS,  &ctx.old_sa_bus,  NULL);
		sigaction(SIGSEGV, &ctx.old_sa_segv, NULL);
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
	/* Static storage so workers that outlive the frame (leak path) can
	 * still dereference their ctx pointers safely. */
	static struct v2_racer_ctx rctx;
	static struct v2_fault_ctx fctx;
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

	/* Belt-and-suspenders: WAKE the registered dst range to kick any
	 * fault still pending in the kernel before we join the threads. */
	{
		struct uffdio_range wr;

		wr.start = (uintptr_t)dst;
		wr.len   = (uint64_t)len;
		(void)ioctl(fd, UFFDIO_WAKE, &wr);
	}

	{
		struct timespec ts = { .tv_sec = 0, .tv_nsec = V3_JOIN_SLEEP_NS };
		int spin;
		bool leaked = false;

		if (racer_started) {
			for (spin = 0; spin < V3_JOIN_LOOPS; spin++) {
				if (pthread_tryjoin_np(racer_tid, NULL) == 0)
					break;
				nanosleep(&ts, NULL);
			}
			if (spin >= V3_JOIN_LOOPS)
				leaked = true; /* worker live: leak, skip munmap */
		}
		if (fault_started) {
			for (spin = 0; spin < V3_JOIN_LOOPS; spin++) {
				if (pthread_tryjoin_np(fault_tid, NULL) == 0)
					break;
				nanosleep(&ts, NULL);
			}
			if (spin >= V3_JOIN_LOOPS)
				leaked = true; /* worker live: leak, skip munmap */
		}
		if (leaked)
			return; /* mappings deliberately leaked; child exit reclaims */
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
	/* Saved pre-V3 signal dispositions; restored by run_variant3() after
	 * thread join.  Written by v3_fault_thread() before any fault access. */
	struct sigaction old_sa_segv;
	struct sigaction old_sa_bus;
};

static _Thread_local sigjmp_buf v3_escape_buf;
static _Thread_local volatile int v3_in_escape_zone;

static void v3_sig_handler(int signo, siginfo_t *info, void *ctx)
{
	(void)info;
	(void)ctx;
	if (v3_in_escape_zone) {
		siglongjmp(v3_escape_buf, 1);
	} else {
		/*
		 * Signal arrived outside the escape zone — not from a V3
		 * teardown race.  SA_RESETHAND has already reset the disposition
		 * to SIG_DFL; re-raise so the default action (core/terminate)
		 * applies instead of silently returning, which would re-execute
		 * the faulting instruction and spin indefinitely.
		 */
		raise(signo);
	}
}

static void *v3_fault_thread(void *arg)
{
	struct v3_fault_ctx *fctx = (struct v3_fault_ctx *)arg;
	struct sigaction sa;
	volatile uint32_t *pg;

	/* Install SIGSEGV/SIGBUS handler for this thread.
	 * sigaction() is process-wide, not per-thread; save the previous
	 * dispositions in fctx so run_variant3() can restore them after join. */
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = v3_sig_handler;
	sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGSEGV, &sa, &fctx->old_sa_segv);
	sigaction(SIGBUS,  &sa, &fctx->old_sa_bus);

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
	/* Static storage so a worker that outlives the frame (leak path) can
	 * still dereference its fctx pointer without hitting a dead stack frame. */
	static struct v3_fault_ctx fctx;
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
	(void)feats;	/* negotiated for future feature gates; unused in V3 */

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
		/* Best-effort WAKE to kick any fault still pending in the kernel;
		 * the teardown action may have already unblocked the thread via
		 * SIGSEGV/SIGBUS, so errors here are ignored. */
		if (fd >= 0 && region != MAP_FAILED) {
			struct uffdio_range wr;

			wr.start = (uintptr_t)region;
			wr.len   = (uint64_t)len;
			(void)ioctl(fd, UFFDIO_WAKE, &wr);
		}
		ts.tv_sec  = 0;
		ts.tv_nsec = V3_JOIN_SLEEP_NS;
		for (spin = 0; spin < V3_JOIN_LOOPS; spin++) {
			if (pthread_tryjoin_np(tid, NULL) == 0)
				break;
			nanosleep(&ts, NULL);
		}
		if (spin >= V3_JOIN_LOOPS)
			return; /* worker still live: leak mappings, skip cleanup */
		/*
		 * Restore signal dispositions — sigaction() is process-wide,
		 * not per-thread; must be undone before this childop returns.
		 * fctx is static storage so old_sa_* are always readable.
		 * Must come AFTER the leak-path check above: on the leak path
		 * the worker is still live and its sigsetjmp escape depends on
		 * the handler remaining installed.
		 */
		sigaction(SIGSEGV, &fctx.old_sa_segv, NULL);
		sigaction(SIGBUS,  &fctx.old_sa_bus,  NULL);
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
