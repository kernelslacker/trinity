/*
 * Part of the recipe_runner catalogue; see recipe-runner.c for the
 * design rationale and recipe-runner-internal.h for the shared
 * declarations and macros.
 */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <linux/io_uring.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "syscall-gate.h"
#include "childops/io_uring/recipes.h"
#include "compat.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "pids.h"

#include "childops/recipe-runner-internal.h"

/*
 * Racer thread for recipe_timerfd_xclose.  Blocks in poll() with a
 * bounded timeout, then drains a single non-blocking read on the
 * (possibly already-closed) timerfd.  Both calls have hard ceilings:
 * poll's is the timeout argument; read inherits TFD_NONBLOCK so it
 * returns immediately with EAGAIN/EBADF/EINVAL regardless of whether
 * the close raced ahead, mid-syscall, or behind it.
 *
 * EBADF on either call is the fdget-vs-close lookup race we are
 * hunting; success on read is the close-after-read-completed sub-
 * window where the timer expired before the close landed.
 */
struct timerfd_xclose_racer_arg {
	int tfd;
};

static void *timerfd_xclose_racer_thread(void *arg)
{
	struct timerfd_xclose_racer_arg *ra = arg;
	struct pollfd pfd;
	uint64_t expirations;
	ssize_t r __unused__;

	pfd.fd = ra->tfd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	(void)poll(&pfd, 1, RECIPE_RACER_TIMEOUT_MS);

	r = read(ra->tfd, &expirations, sizeof(expirations));
	return NULL;
}

/*
 * Recipe 26: timerfd cross-thread close-vs-read race.
 *
 * Per cycle (1..MAX_CYCLES):
 *
 *   timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC) ->
 *   timerfd_settime(50ms initial + 50ms periodic) -> spawn racer
 *   thread blocked in poll(POLLIN, 100ms) + read() -> usleep 0..100us
 *   race-window jitter -> close(tfd) (the race) -> pthread_join.
 *
 * Targets the kernel paths timerfd_release, timerfd_remove_cancel_on_set,
 * and the wait-queue cleanup that fire when a timerfd is destroyed
 * while another task is mid-poll() or mid-read() on it.  Threads share
 * the fdtable, which is the bug class -- a sibling process closing the
 * same numeric fd in its own table never races with our fdget.  Distinct
 * from recipe 1 (recipe_timerfd) which runs settime/read/gettime
 * serially on a single thread; this one drives the *concurrent*
 * read-vs-close window.
 *
 * Bounded racer syscalls (poll with timeout, read on TFD_NONBLOCK fd)
 * mean plain pthread_join always returns within ~100ms.  Sidesteps the
 * wedge problem where pthread_cancel against a thread stuck in an
 * uninterruptible read is unreliable and detached threads leak state.
 *
 * THREAD_SPAWN_LATCH=3 consecutive pthread_create failures bails for
 * the rest of the invocation -- under nproc/thread limits the EAGAIN
 * won't lift mid-op while fork_storm or cgroup_churn are competing for
 * the budget.
 *
 * timerfd may be missing on stripped-down kernels (no
 * CONFIG_TIMERFD_CREATE).  ENOSYS / EINVAL / EPERM on the very first
 * timerfd_create latches the recipe off via *unsupported.
 *
 * Returns ok=true if any cycle reached close+join.  Per-cycle failures
 * are tolerated mid-loop because one bad cycle (e.g. ephemeral resource
 * pressure under sibling load) shouldn't penalise the whole recipe.
 */
#define RECIPE_TIMERFD_XCLOSE_MAX_CYCLES	4

bool recipe_timerfd_xclose(bool *unsupported)
{
	struct itimerspec its;
	unsigned int cycles;
	unsigned int i;
	unsigned int spawn_fail_streak = 0;
	unsigned int completed = 0;
	bool spawn_latched = false;

	cycles = 1 + rnd_modulo_u32(RECIPE_TIMERFD_XCLOSE_MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		struct timerfd_xclose_racer_arg ra;
		pthread_t tid;
		int tfd;
		int rc;

		tfd = timerfd_create(CLOCK_MONOTONIC,
				     TFD_NONBLOCK | TFD_CLOEXEC);
		if (tfd < 0) {
			if (i == 0 && (errno == ENOSYS || errno == EINVAL ||
				       errno == EPERM)) {
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
				return false;
			}
			continue;
		}

		memset(&its, 0, sizeof(its));
		its.it_value.tv_sec = 0;
		its.it_value.tv_nsec = 50 * 1000 * 1000;	/* 50 ms */
		its.it_interval.tv_sec = 0;
		its.it_interval.tv_nsec = 50 * 1000 * 1000;
		if (timerfd_settime(tfd, 0, &its, NULL) < 0) {
			close(tfd);
			continue;
		}

		ra.tfd = tfd;
		rc = pthread_create(&tid, NULL,
				    timerfd_xclose_racer_thread, &ra);
		if (rc != 0) {
			close(tfd);
			if (++spawn_fail_streak >= RECIPE_THREAD_SPAWN_LATCH) {
				spawn_latched = true;
				break;
			}
			continue;
		}
		spawn_fail_streak = 0;

		/* Variable race window -- 0..100us picks a random sub-window
		 * of the racer's poll/read to land the close in. */
		if ((rnd_u32() & 0xff) != 0)
			usleep((useconds_t)rnd_modulo_u32(101));

		(void)close(tfd);

		(void)pthread_join(tid, NULL);

		completed++;
	}

	/* If every cycle was lost to pthread_create EAGAIN under sibling
	 * thread pressure, that's transient nproc/thread exhaustion -- not
	 * a recipe failure.  Skip rather than score a partial, which would
	 * keep the picker re-selecting us against a kernel path we never
	 * actually exercised. */
	if (completed == 0 && spawn_latched)
		return true;

	return completed > 0;
}

/*
 * Recipe 27: signalfd queue-drain and mask-update lifecycle.
 *
 * Single-threaded.  Block 3 RT signals via sigprocmask, attach a
 * signalfd watching all 3, queue 3 sigqueue() deliveries with payloads,
 * drain via read() in a loop until EAGAIN, update the signalfd mask
 * via signalfd(sfd, &reduced) to drop one watched signal, queue one
 * more delivery on the dropped signal and one on a still-watched
 * signal, drain via read() again, then drain any residual via
 * sigtimedwait() so nothing is pending when we restore the original
 * mask.
 *
 * Distinct from recipe 5 (recipe_signalfd) which only drives
 * create / EAGAIN-read / close on a single signal with no actual
 * delivery.  This recipe drives:
 *   - the multi-entry signalfd_read path (multiple struct
 *     signalfd_siginfo packed into one read buffer when the queue
 *     holds more than one)
 *   - the signalfd update-mask path (signalfd() with a non-(-1) fd
 *     argument), which lives on the signalfd_setup_pipe / context
 *     update path and rewires ctx->sigmask while the fd is still
 *     installed
 *   - the queue accounting that has to keep dropped-signal
 *     deliveries out of the signalfd reader's view but still in the
 *     task's pending set for sigtimedwait to drain
 *
 * Random callers of signalfd() rarely target an existing fd to update
 * its mask, and almost never inject sigqueue() with payloads against
 * an fd they're about to drain, so the multi-entry read + mask-update
 * path stays cold without a deliberate driver.
 *
 * sigtimedwait drain on the way out is mandatory: an unblocked SIGRT
 * with a delivery still queued in task->pending would fire on the
 * sigprocmask restore and either kill the child or get caught by
 * Trinity's signal handler with confusing provenance.
 *
 * Latch shape covers every way the feature can be absent:
 *   - signalfd() ENOSYS         (CONFIG_SIGNALFD off, very stripped)
 *   - signalfd() update EINVAL  (kernel rejects mask-update via an
 *                                extant fd under specific config combos)
 */
bool recipe_signalfd_delivery(bool *unsupported)
{
	sigset_t ss, reduced, oldss;
	struct signalfd_siginfo buf[8];
	union sigval sv;
	struct timespec zero_ts;
	siginfo_t drained;
	pid_t self;
	ssize_t r __unused__;
	int sigs[3];
	int sfd = -1;
	bool mask_saved = false;
	bool ok = false;

	/* SIGRTMIN+8..+10 -- well clear of glibc's reserved RT signals
	 * and Trinity's own SIGALRM/SIGXCPU/SIGINT.  Matches the
	 * existing recipe_signalfd's RT-signal regime. */
	sigs[0] = SIGRTMIN + 8;
	sigs[1] = SIGRTMIN + 9;
	sigs[2] = SIGRTMIN + 10;
	if (sigs[2] >= SIGRTMAX)
		goto out;

	sigemptyset(&ss);
	sigaddset(&ss, sigs[0]);
	sigaddset(&ss, sigs[1]);
	sigaddset(&ss, sigs[2]);
	if (sigprocmask(SIG_BLOCK, &ss, &oldss) < 0)
		goto out;
	mask_saved = true;

	sfd = signalfd(-1, &ss, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sfd < 0) {
		if (errno == ENOSYS) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	self = mypid();

	/* Queue three deliveries, one per watched signal, with distinct
	 * payloads.  sigqueue() routes through the per-signal pending
	 * queue with a real siginfo; plain raise() / kill() take a fast
	 * path that elides the queue entry. */
	sv.sival_int = 0x10;
	(void)sigqueue(self, sigs[0], sv);
	sv.sival_int = 0x20;
	(void)sigqueue(self, sigs[1], sv);
	sv.sival_int = 0x30;
	(void)sigqueue(self, sigs[2], sv);

	/* Drain the signalfd until EAGAIN.  Each read pulls 1..N
	 * struct signalfd_siginfo entries; the kernel packs as many as
	 * fit in our buffer and the queue holds. */
	while ((r = read(sfd, buf, sizeof(buf))) > 0)
		;

	/* Update mask via signalfd() with the existing fd -- drops
	 * sigs[2] from the watched set.  Drives the mask-update path
	 * that random callers rarely hit. */
	sigemptyset(&reduced);
	sigaddset(&reduced, sigs[0]);
	sigaddset(&reduced, sigs[1]);
	if (signalfd(sfd, &reduced, SFD_NONBLOCK | SFD_CLOEXEC) < 0) {
		if (errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	/* Inject the dropped signal -- it should land in task->pending
	 * but stay invisible to the signalfd reader -- plus a still-
	 * watched one.  Best-effort: a kernel bug here is exactly what
	 * we want exposed, so we don't assert on the read return. */
	sv.sival_int = 0x40;
	(void)sigqueue(self, sigs[2], sv);
	sv.sival_int = 0x50;
	(void)sigqueue(self, sigs[0], sv);

	while ((r = read(sfd, buf, sizeof(buf))) > 0)
		;

	ok = true;
out:
	if (sfd >= 0)
		close(sfd);

	/* Drain any residual pending signals before restoring the mask.
	 * sigtimedwait with a zero timeout is the only safe way to
	 * dequeue a sigqueue() delivery that signalfd's mask-update
	 * dropped from view but left in task->pending. */
	if (mask_saved) {
		zero_ts.tv_sec = 0;
		zero_ts.tv_nsec = 0;
		while (sigtimedwait(&ss, &drained, &zero_ts) >= 0)
			;
		(void)sigprocmask(SIG_SETMASK, &oldss, NULL);
	}
	return ok;
}

/*
 * Recipe 28: epoll watched-fd implicit-close lifecycle.
 *
 * Single-threaded.  epoll_create1 -> create N (=4) eventfds ->
 * EPOLL_CTL_ADD all of them -> close half of them WITHOUT
 * EPOLL_CTL_DEL first (kernel must do the implicit removal via
 * eventpoll_release_file in __fput) -> EPOLL_CTL_ADD a fresh fd to
 * exercise the rb-tree against the just-mutated tree -> epoll_wait
 * (0ms) to walk rdllist and per-epitem ready-list -> EPOLL_CTL_DEL
 * the surviving registrations explicitly -> close everything.
 *
 * Drives the eventpoll_release_file -> ep_remove path that fires when
 * a watched fd is closed without being explicitly EPOLL_CTL_DEL'd
 * first.  The file's f_ep list management has to drop the struct
 * epitem ref atomically with the fd close, walking back into the epoll
 * instance's rbtree and rdllist from the file side -- the path with
 * a long history of UAFs and refcount mismatches.
 *
 * Distinct from recipe 4 (recipe_epoll) which only drives the explicit
 * ADD/MOD/DEL path on a single watched fd.  This recipe is the close-
 * without-DEL variant -- the implicit removal that the standard
 * recipe never reaches.  Random callers of close() rarely close a fd
 * that's currently registered on an epoll set, so the implicit-removal
 * edge stays cold without a deliberate driver.
 *
 * Adding a fresh fd between the implicit-close burst and the
 * epoll_wait drives the rb-tree insertion against a tree the implicit
 * cleanup just mutated -- the path most likely to expose ordering
 * bugs in the rb-tree update under a concurrent ep_release walk.
 *
 * Latch shape covers the ways the feature can be absent on the very
 * first epoll_create1:
 *   - ENOSYS  (CONFIG_EPOLL off, very stripped)
 * Plus EINVAL on the first EPOLL_CTL_ADD with EPOLLIN against an
 * eventfd, which is implausible in practice but flags a half-wired
 * epoll surface (the create syscall present, the ctl path stubbed).
 */
#define RECIPE_EPOLL_XCLOSE_NFDS	4

bool recipe_epoll_xclose(bool *unsupported)
{
	struct epoll_event ev;
	struct epoll_event evs[RECIPE_EPOLL_XCLOSE_NFDS + 1];
	int evfds[RECIPE_EPOLL_XCLOSE_NFDS];
	int extra = -1;
	int epfd = -1;
	unsigned int i;
	bool ok = false;

	for (i = 0; i < ARRAY_SIZE(evfds); i++)
		evfds[i] = -1;

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0) {
		if (errno == ENOSYS) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(evfds); i++) {
		evfds[i] = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (evfds[i] < 0)
			goto out;

		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN | EPOLLET;
		ev.data.fd = evfds[i];
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, evfds[i], &ev) < 0) {
			if (i == 0 && errno == EINVAL) {
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
			}
			goto out;
		}
	}

	/* Close half of the watched fds without an EPOLL_CTL_DEL first.
	 * The kernel must drop the corresponding epitem entries via
	 * eventpoll_release_file as part of __fput.  No EPOLL_CTL_DEL =
	 * the implicit-removal path is what we want to drive. */
	for (i = 0; i < ARRAY_SIZE(evfds) / 2; i++) {
		close(evfds[i]);
		evfds[i] = -1;
	}

	/* Add a fresh fd after the implicit removals -- exercises the
	 * rb-tree insertion against a tree the implicit-cleanup path
	 * just mutated. */
	extra = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (extra >= 0) {
		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN;
		ev.data.fd = extra;
		(void)epoll_ctl(epfd, EPOLL_CTL_ADD, extra, &ev);
	}

	/* Drain whatever's ready.  Best-effort -- the eventfds are all
	 * 0 so nothing is expected, but the wait still walks rdllist
	 * and the per-epitem ready-list which is the path under test. */
	(void)epoll_wait(epfd, evs, ARRAY_SIZE(evs), 0);

	/* Tear down the surviving registrations explicitly so we
	 * exercise both ep_remove paths in one recipe. */
	for (i = ARRAY_SIZE(evfds) / 2; i < ARRAY_SIZE(evfds); i++) {
		if (evfds[i] >= 0) {
			(void)epoll_ctl(epfd, EPOLL_CTL_DEL, evfds[i], NULL);
			close(evfds[i]);
			evfds[i] = -1;
		}
	}

	if (extra >= 0) {
		(void)epoll_ctl(epfd, EPOLL_CTL_DEL, extra, NULL);
		close(extra);
		extra = -1;
	}

	ok = true;
out:
	for (i = 0; i < ARRAY_SIZE(evfds); i++)
		if (evfds[i] >= 0)
			close(evfds[i]);
	if (extra >= 0)
		close(extra);
	if (epfd >= 0)
		close(epfd);
	return ok;
}

/*
 * Recipe 29: io_uring fixed-file register/unregister vs in-flight ref.
 *
 * Single-threaded.  Set up a private io_uring, mmap the SQ/CQ rings and
 * SQE array, IORING_REGISTER_FILES with one /dev/null fd in slot 0,
 * close the original /dev/null fd so the registered table holds the
 * sole reference, submit IORING_OP_READ on fixed-file index 0 with
 * IOSQE_FIXED_FILE via io_uring_enter(to_submit=1, min_complete=0)
 * (submit-and-return without reaping), then IORING_UNREGISTER_FILES
 * back-to-back.  Drain any CQEs and tear down.
 *
 * Targets the fixed-file refcount machinery in fs/io_uring/rsrc.c —
 * the in-flight request grabs a ref on the registered slot via the
 * rsrc_node mechanism, and UNREGISTER must reconcile the slot release
 * against any extant refs.  /dev/null EOF means the read completes
 * inline in the common case, but under sibling load (mm pressure,
 * scheduler preemption) the dispatch can defer to io-wq and the
 * unregister observes a non-zero rsrc-node refcount.  The exact
 * window is small but the path under test — io_rsrc_node_destroy /
 * io_rsrc_data_free / io_wait_rsrc_data — is the same one with a
 * recurring history of UAFs and double-frees in this subsystem.
 *
 * Closing the original /dev/null fd between REGISTER and the SQE
 * submit is intentional: it forces the registered table to be the
 * sole owner of the file's struct file ref.  When the read references
 * the file via the registered index, the lookup goes through the
 * rsrc node, not the caller's fdtable — which is exactly the path
 * the bug class lives on.
 *
 * Single-threaded variant rather than the 2-thread shape used by
 * recipe 26 (recipe_timerfd_xclose) because UNREGISTER_FILES is
 * synchronous against in-flight refs: a 2nd thread would have to
 * cancel the request before unregister returned, complicating the
 * sequence without buying any additional path coverage.
 *
 * Latch shape covers the ways the feature can be absent on the very
 * first probe:
 *   - io_uring_setup ENOSYS    (CONFIG_IO_URING off)
 *   - io_uring_setup EPERM     (kernel.io_uring_disabled sysctl)
 *   - mmap MAP_FAILED with EOPNOTSUPP/EPERM on the very first try
 *     (locked-down kernels that present the syscall but reject mmap)
 *   - REGISTER_FILES EINVAL/ENOSYS on first call (half-wired surface)
 */
bool recipe_iouring_fixed_uaf(bool *unsupported)
{
	struct iour_ring ctx;
	struct io_uring_params p;
	enum iour_setup_status st;
	struct io_uring_sqe *sqes_arr;
	int devnull = -1;
	int fds[1];
	unsigned int *sq_array;
	unsigned int mask, head, tail;
	bool registered = false;
	bool ok = false;
	int r;

	/* No RAND_NEGATIVE_OR wrap on the entries count: the UAF
	 * reproducer's hit rate depends on the kernel allocating a ring
	 * with the requested 8-entry shape every iteration.  An
	 * edge-value substitution (0, -1, INT_MAX, ...) would either
	 * fail the setup outright or yield a differently-shaped ring --
	 * both dilute this recipe's race window without adding coverage
	 * the other ring callers don't already provide.
	 *
	 * The helper's 3-state status replaces the old setup-then-
	 * inspect-errno classification: IOUR_UNSUPPORTED means the
	 * kernel will never support io_uring on this host (CONFIG off,
	 * sysctl off, persistently rejected), so we latch
	 * *unsupported.  IOUR_TRANSIENT (ENOMEM/EAGAIN/EMFILE, an
	 * overflow-rejected hostile kernel return, an mmap blip) skips
	 * the recipe without latching -- the next dispatch may well
	 * succeed. */
	memset(&p, 0, sizeof(p));
	st = iour_ring_setup(&p, 8U, &ctx);
	if (st != IOUR_SUPPORTED) {
		if (st == IOUR_UNSUPPORTED) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (devnull < 0)
		goto out;

	fds[0] = devnull;
	r = (int)trinity_raw_syscall(__NR_io_uring_register, ctx.fd,
			 IORING_REGISTER_FILES, fds, 1U);
	if (r < 0) {
		if (errno == ENOSYS || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}
	registered = true;

	/* Drop the caller's fdtable ref now that the registered table owns
	 * a ref on the same struct file.  Subsequent ops via the fixed-file
	 * index route through the rsrc_node lookup -- the path the UAF
	 * class lives on, not the regular fdget. */
	close(devnull);
	devnull = -1;

	sqes_arr = (struct io_uring_sqe *)ctx.sqes;
	memset(&sqes_arr[0], 0, sizeof(sqes_arr[0]));
	sqes_arr[0].opcode    = IORING_OP_READ;
	sqes_arr[0].fd        = 0;		/* registered slot index */
	sqes_arr[0].flags     = IOSQE_FIXED_FILE;
	sqes_arr[0].len       = 16;
	sqes_arr[0].user_data = 0xfeedface;

	mask = *(volatile unsigned int *)((char *)ctx.sq_ring + ctx.sq_off_mask);
	head = *(volatile unsigned int *)((char *)ctx.sq_ring + ctx.sq_off_head);
	tail = *(volatile unsigned int *)((char *)ctx.sq_ring + ctx.sq_off_tail);
	if ((tail - head) >= ctx.sq_entries)
		goto out;

	sq_array = (unsigned int *)((char *)ctx.sq_ring + ctx.sq_off_array);
	sq_array[tail & mask] = 0;
	__sync_synchronize();
	*(volatile unsigned int *)((char *)ctx.sq_ring + ctx.sq_off_tail) = tail + 1;

	/* Submit-and-return: min_complete=0 means we don't wait for the
	 * read to land in the CQ before kicking off the unregister.  The
	 * race window is the gap between the kernel queueing the request
	 * (which grabs the rsrc-node ref) and posting the completion
	 * (which drops it). */
	(void)trinity_raw_syscall(__NR_io_uring_enter, ctx.fd, 1U, 0U,
		      0U /* no GETEVENTS */, NULL, 0UL);

	(void)trinity_raw_syscall(__NR_io_uring_register, ctx.fd,
		      IORING_UNREGISTER_FILES, NULL, 0U);
	registered = false;

	/* Drain any CQEs that landed before/during the unregister.  No
	 * assertion on what we find -- the path under test is the
	 * unregister vs in-flight ref reconciliation, not whether the
	 * read returned 0 or -ECANCELED. */
	{
		unsigned int chead, ctail;

		chead = *(volatile unsigned int *)((char *)ctx.cq_ring +
						   ctx.cq_off_head);
		ctail = *(volatile unsigned int *)((char *)ctx.cq_ring +
						   ctx.cq_off_tail);
		while (chead != ctail)
			chead++;
		__sync_synchronize();
		*(volatile unsigned int *)((char *)ctx.cq_ring +
					   ctx.cq_off_head) = chead;
	}

	ok = true;
out:
	if (registered)
		(void)trinity_raw_syscall(__NR_io_uring_register, ctx.fd,
			      IORING_UNREGISTER_FILES, NULL, 0U);
	if (devnull >= 0)
		close(devnull);
	iour_ring_teardown(&ctx);
	return ok;
}
