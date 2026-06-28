/*
 * iouring-recipes-poll-timeout -- POLL_ADD / POLL_REMOVE / TIMEOUT /
 * TIMEOUT_REMOVE / LINK_TIMEOUT / ASYNC_CANCEL / EPOLL_WAIT /
 * EPOLL_CTL / FUTEX_WAIT_WAKE / WAITID recipe family for the
 * iouring-recipes catalogue.
 *
 * Recipes here all exercise a wait / cancel / timeout dispatch path.
 * recipe_futex_wait_wake draws from the parent's mapping pool and
 * publishes its drawn range to the pool-race statics defined in
 * iouring-recipes.c so the dispatcher's fault handler can route an
 * in-range SEGV/SIGBUS to the sigsetjmp landing pad.
 *
 * See childops/iouring-recipes.c for the dispatcher and the shared
 * pool-race fault handler; see iouring-recipes-internal.h for the
 * cross-TU symbol boundary.
 */

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include <linux/io_uring.h>
#include <string.h>

#include "compat.h"
#include "errno-classify.h"
#include "maps.h"
#include "shm.h"
#include "stats.h"
#include "syscall-gate.h"
#include "trinity.h"
#include "utils.h"

#include "childops/iouring-recipes-internal.h"

/* ------------------------------------------------------------------ *
 * Recipe 2: TIMEOUT with IOSQE_IO_DRAIN
 *
 * Submit a NOP then a TIMEOUT with IOSQE_IO_DRAIN set.  Drain ordering
 * requires the kernel to complete all prior SQEs before starting the
 * timeout countdown — this exercises the drain-flag dispatch path and
 * the timeout-vs-drain interaction.
 * ------------------------------------------------------------------ */
bool recipe_timeout_drain(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqes[2];
	struct __kernel_timespec ts;
	int r;

	sqe_clear(&sqes[0]);
	sqes[0].opcode    = IORING_OP_NOP;
	sqes[0].flags     = IOSQE_IO_DRAIN;
	sqes[0].user_data = 10;

	ts.tv_sec  = 0;
	ts.tv_nsec = 1000000;	/* 1 ms */

	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_TIMEOUT;
	sqes[1].flags     = IOSQE_IO_DRAIN;
	sqes[1].addr      = (__u64)(uintptr_t)&ts;
	sqes[1].len       = 1;
	sqes[1].user_data = 11;

	if (!iour_submit_sqes(ctx, sqes, 2))
		return false;

	r = iour_enter(ctx, 2, 1);
	if (r < 0)
		return false;

	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe 3: POLL_ADD multi-shot + POLL_REMOVE
 *
 * Create an eventfd, register a POLL_ADD with IORING_POLL_ADD_MULTI
 * so the kernel installs a persistent poll-wait, then immediately
 * submit a POLL_REMOVE targeting the same user_data.  This races the
 * removal against the poll-wait registration — the kernel must handle
 * the cancellation regardless of which path wins.
 * ------------------------------------------------------------------ */
#ifndef IORING_POLL_ADD_MULTI
#define IORING_POLL_ADD_MULTI	(1U << 0)
#endif

bool recipe_poll_multishot(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqes[2];
	bool ok = false;
	int r;

	s->evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (s->evfd < 0)
		goto out;

	/* POLL_ADD with IORING_POLL_ADD_MULTI (multi-shot). */
	sqe_clear(&sqes[0]);
	sqes[0].opcode        = IORING_OP_POLL_ADD;
	sqes[0].fd            = s->evfd;
	sqes[0].poll32_events = POLLIN;
	sqes[0].len           = IORING_POLL_ADD_MULTI;
	sqes[0].user_data     = 20;

	/* POLL_REMOVE by user_data to cancel the multi-shot above. */
	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_POLL_REMOVE;
	sqes[1].addr      = 20;
	sqes[1].user_data = 21;

	if (!iour_submit_sqes(ctx, sqes, 2))
		goto out;

	r = iour_enter(ctx, 2, 1);
	if (r < 0)
		goto out;

	iour_drain_cqes(ctx);
	ok = true;
out:
	return ok;
}

/* ------------------------------------------------------------------ *
 * Recipe 8: ASYNC_CANCEL on an in-flight op
 *
 * Submit a POLL_ADD that won't fire (eventfd stays at zero) so it
 * remains pending in the ring, then immediately cancel it via
 * IORING_OP_ASYNC_CANCEL targeting the same user_data.  This is the
 * canonical cancellation race that surfaces in io_uring CVEs involving
 * use-after-free on the request-completion path when a cancel races
 * the natural completion.
 * ------------------------------------------------------------------ */
bool recipe_async_cancel(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqes[2];
	bool ok = false;
	int r;

	s->evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (s->evfd < 0)
		goto out;

	/* POLL_ADD that won't fire — stays pending. */
	sqe_clear(&sqes[0]);
	sqes[0].opcode        = IORING_OP_POLL_ADD;
	sqes[0].fd            = s->evfd;
	sqes[0].poll32_events = POLLIN;
	sqes[0].user_data     = 70;

	/* ASYNC_CANCEL targeting user_data=70. */
	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_ASYNC_CANCEL;
	sqes[1].addr      = 70;
	sqes[1].user_data = 71;

	if (!iour_submit_sqes(ctx, sqes, 2))
		goto out;

	r = iour_enter(ctx, 2, 1);
	if (r < 0)
		goto out;

	iour_drain_cqes(ctx);
	ok = true;
out:
	return ok;
}

/* ------------------------------------------------------------------ *
 * Recipe 14: FUTEX_WAIT + FUTEX_WAKE via io_uring
 *
 * Draw a shared-anon region from the parent's inherited mapping pool,
 * submit IORING_OP_FUTEX_WAIT with an expected value that doesn't match
 * (fast EAGAIN path), then IORING_OP_FUTEX_WAKE on the same address.
 * Exercises the io_uring futex dispatch path added in Linux 6.7.  First
 * ENOSYS latches the recipe off.
 * ------------------------------------------------------------------ */
#ifndef TRINITY_COMPAT_BACKFILLED_FUTEX_WAIT_WAKE
bool recipe_futex_wait_wake(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqes[2];
	struct map *m = NULL;
	uint32_t *addr = NULL;
	bool ok = false;
	int r;

	/* Draw the futex backing storage from the parent's inherited
	 * mapping pool.  Sibling iouring children draw from the same pool,
	 * so multiple rings will sometimes target the same futex word —
	 * that overlap is the CV.4 target, exercising io_uring's futex
	 * dispatch and the kernel's shared-key hash bucket against
	 * cross-sibling waiters and wakers on identical keys.
	 *
	 * The pool owns the mapping: do NOT munmap on cleanup.
	 *
	 * Filter the pool draw on PROT_READ | PROT_WRITE: the recipe stores
	 * to the value word before submission and the kernel reads it during
	 * the cmpxchg in the FUTEX_WAIT op handler.  PROT_READ-only or
	 * PROT_NONE pool entries would SEGV on the value-word store before
	 * the SQE is ever submitted. */
	m = get_map_with_prot(PROT_READ | PROT_WRITE);
	if (m == NULL) {
		/* No PROT_READ|PROT_WRITE pool entry to back the futex
		 * word — without it the recipe can't even reach SQE
		 * submission.  Latch off rather than re-pick forever. */
		*unsupported = true;
		__atomic_add_fetch(&shm->stats.iouring_recipes_enosys, 1,
				   __ATOMIC_RELAXED);
		goto out;
	}
	addr = (uint32_t *)m->ptr;

	/* Publish drawn pool range — see recipe_fixed_buffer_read for the
	 * full rationale.  The value-word store below is the first
	 * userspace deref of the pool entry and the most likely fault
	 * site if a sibling has unmapped between the draw and now. */
	iouring_recipes_pool_race_addr_low  = (uintptr_t)m->ptr;
	iouring_recipes_pool_race_addr_high = (uintptr_t)m->ptr + m->size;

	*addr = 0;

	/* FUTEX_WAIT with val=1 — mismatches *addr=0, returns EAGAIN. */
	sqe_clear(&sqes[0]);
	sqes[0].opcode      = IORING_OP_FUTEX_WAIT;
	sqes[0].fd          = FUTEX_BITSET_MATCH_ANY;
	sqes[0].addr        = (__u64)(uintptr_t)addr;
	sqes[0].addr2       = 1;
	sqes[0].futex_flags = FUTEX_PRIVATE_FLAG;
	sqes[0].user_data   = 130;

	sqe_clear(&sqes[1]);
	sqes[1].opcode      = IORING_OP_FUTEX_WAKE;
	sqes[1].fd          = FUTEX_BITSET_MATCH_ANY;
	sqes[1].addr        = (__u64)(uintptr_t)addr;
	sqes[1].off         = INT_MAX;
	sqes[1].futex_flags = FUTEX_PRIVATE_FLAG;
	sqes[1].user_data   = 131;

	if (!iour_submit_sqes(ctx, sqes, 2))
		goto out;

	r = iour_enter(ctx, 2, 1);
	if (r < 0) {
		if (is_syscall_unsupported(errno) || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}

	iour_drain_cqes(ctx);
	ok = true;
out:
	return ok;
}
#endif /* TRINITY_COMPAT_BACKFILLED_FUTEX_WAIT_WAKE */

/* ------------------------------------------------------------------ *
 * Recipe 15: EPOLL_WAIT via io_uring
 *
 * Create an epoll fd with an eventfd registered, then submit
 * IORING_OP_EPOLL_WAIT with timeout_ms=0.  Nothing is ready so the
 * wait returns immediately, but the kernel walks the epoll wait-list
 * setup and teardown path inside io_uring's implementation.  Added in
 * Linux 6.15; first ENOSYS/EINVAL latches the recipe off.
 * ------------------------------------------------------------------ */
bool recipe_epoll_wait(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct epoll_event ev;
	struct epoll_event evs[4];
	bool ok = false;
	int r;

	s->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (s->epoll_fd < 0)
		goto out;

	s->evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (s->evfd < 0)
		goto out;

	memset(&ev, 0, sizeof(ev));
	ev.events  = EPOLLIN;
	ev.data.fd = s->evfd;
	if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->evfd, &ev) < 0)
		goto out;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_EPOLL_WAIT;
	sqe.fd        = s->epoll_fd;
	sqe.addr      = (__u64)(uintptr_t)evs;
	sqe.len       = ARRAY_SIZE(evs);
	sqe.off       = 0;
	sqe.user_data = 140;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		goto out;

	r = iour_enter(ctx, 1, 1);
	if (r < 0) {
		if (is_syscall_unsupported(errno) || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}

	iour_drain_cqes(ctx);
	ok = true;
out:
	return ok;
}

/* ------------------------------------------------------------------ *
 * Recipe: EPOLL_CTL — add an eventfd to an epoll set via the ring
 *
 * SQE layout: sqe->fd=epfd, sqe->len=op, sqe->off=target fd,
 *             sqe->addr=epoll_event*.
 * ------------------------------------------------------------------ */
bool recipe_epoll_ctl(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct epoll_event ev;
	int r;

	s->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (s->epoll_fd < 0)
		return false;
	s->evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (s->evfd < 0)
		return false;

	memset(&ev, 0, sizeof(ev));
	ev.events  = EPOLLIN;
	ev.data.fd = s->evfd;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_EPOLL_CTL;
	sqe.fd        = s->epoll_fd;
	sqe.len       = EPOLL_CTL_ADD;
	sqe.off       = s->evfd;
	sqe.addr      = (__u64)(uintptr_t)&ev;
	sqe.user_data = 350;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: LINK_TIMEOUT chained from a NOP
 *
 * LINK_TIMEOUT only makes sense as the second member of a linked pair;
 * it bounds the time the prior linked op may run.  NOP completes
 * instantly so the timeout itself fires the cancellation path harmlessly.
 * ------------------------------------------------------------------ */
bool recipe_link_timeout(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqes[2];
	struct __kernel_timespec ts;
	int r;

	sqe_clear(&sqes[0]);
	sqes[0].opcode    = IORING_OP_NOP;
	sqes[0].flags     = IOSQE_IO_LINK;
	sqes[0].user_data = 390;

	ts.tv_sec  = 0;
	ts.tv_nsec = 1000000;	/* 1 ms */

	sqe_clear(&sqes[1]);
	sqes[1].opcode        = IORING_OP_LINK_TIMEOUT;
	sqes[1].addr          = (__u64)(uintptr_t)&ts;
	sqes[1].len           = 1;
	sqes[1].timeout_flags = 0;
	sqes[1].user_data     = 391;

	if (!iour_submit_sqes(ctx, sqes, 2))
		return false;
	r = iour_enter(ctx, 2, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: TIMEOUT_REMOVE — submit a long timeout, then yank it
 * ------------------------------------------------------------------ */
bool recipe_timeout_remove(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct __kernel_timespec ts;
	int r;

	ts.tv_sec  = 60;
	ts.tv_nsec = 0;

	sqe_clear(&sqe);
	sqe.opcode        = IORING_OP_TIMEOUT;
	sqe.addr          = (__u64)(uintptr_t)&ts;
	sqe.len           = 1;
	sqe.timeout_flags = 0;
	sqe.user_data     = 400;
	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	if (iour_enter(ctx, 1, 0) < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode        = IORING_OP_TIMEOUT_REMOVE;
	sqe.addr          = 400;
	sqe.timeout_flags = 0;
	sqe.user_data     = 401;
	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 2);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: WAITID on P_ALL with WNOHANG (likely ECHILD)
 *
 * SQE layout: sqe->len=which, sqe->fd=upid, sqe->file_index=options,
 *             sqe->addr2=infop ptr.
 * ------------------------------------------------------------------ */
bool recipe_waitid(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	siginfo_t infop;
	int r;

	memset(&infop, 0, sizeof(infop));

	sqe_clear(&sqe);
	sqe.opcode      = IORING_OP_WAITID;
	sqe.len         = P_ALL;
	sqe.fd          = 0;
	sqe.file_index  = WNOHANG | WEXITED;
	sqe.addr2       = (__u64)(uintptr_t)&infop;
	sqe.user_data   = 500;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0) {
		if (is_syscall_unsupported(errno) || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		return false;
	}
	iour_drain_cqes(ctx);
	return true;
}
