#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <fcntl.h>

#include "child.h"
#include "fd.h"
#include "fds-internal.h"
#include "object-types.h"
#include "objects.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"

int get_new_random_fd(void)
{
	struct fd_provider *provider;
	struct fd_provider *populated[MAX_OBJECT_TYPES];
	unsigned int npop = 0;
	unsigned int retries = 0;
	unsigned int i;
	int fd;

	if (num_active_providers == 0)
		return -1;

	/*
	 * Pre-filter to providers whose OBJ_GLOBAL pool is currently
	 * non-empty.  Without this, uniform random selection across all
	 * active providers wastes draws on syscall-populated pools that
	 * are momentarily empty (sockets, eventfd, timerfd, memfd, pipes,
	 * ...): each empty draw returns -1, which used to bail this
	 * function immediately (the historic `fd >= 0 && fd <= 2` check
	 * silently fell through for fd == -1) and burned a full outer
	 * regen in get_random_fd().  With ~30+ providers and many often
	 * empty under load, the outer 64-retry budget was hitting
	 * exhaustion hundreds of times per child -- each exhaustion
	 * surfaces to the kernel as EBADF, wasting fd-arg syscalls that
	 * should have hit real kernel fd paths and produced coverage.
	 *
	 * The NULL/->get-NULL slot guard is preserved by skipping such
	 * slots here; the canary stat still fires once per scan-detected
	 * invalid entry instead of once per random draw.
	 *
	 * objects_empty() is an O(1) read of head->num_entries -- racy
	 * vs. concurrent updates but only transiently so; worst case we
	 * skip a provider that just got populated, or include one that
	 * just emptied (the inner retry covers the latter).
	 */
	for (i = 0; i < num_active_providers; i++) {
		provider = active_providers[i];
		if (provider == NULL || provider->get == NULL) {
			__atomic_add_fetch(&shm->stats.fd.provider_invalid, 1,
					   __ATOMIC_RELAXED);
			continue;
		}
		if (objects_empty(provider->objtype))
			continue;
		populated[npop++] = provider;
	}

	if (npop == 0)
		return -1;

retry:
	provider = populated[rnd_modulo_u32(npop)];
	fd = provider->get();
	/*
	 * fd <= 2 covers both stdin/stdout/stderr draws and the
	 * transient -1 a provider can hand back when its internal slot
	 * pick loses a race (e.g. fds/eventfd.c's 1000-iter objpool_check
	 * loop bottoms out, OBJ_GLOBAL slot recycle, ...).  Reroll within
	 * the inner budget instead of letting -1 escape to the outer
	 * regen and burn a budgeted retry.
	 */
	if (fd <= 2) {
		if (++retries < 10)
			goto retry;
		return -1;
	}
	return fd;
}

/*
 * Outer-loop retry budget for get_random_fd().  Each iteration of
 * `regen:` re-runs get_new_random_fd() (itself bounded to 10 inner
 * sub-retries) plus the fd_hash_lookup recovery path.  If we still
 * cannot produce a usable fd (>2, tracked-or-over-budget) after this
 * many outer iterations, bail and return -1.  Callers cast the result
 * to unsigned long and pass it as a syscall arg, so an outer-budget
 * bail surfaces to the kernel as EBADF — same handling already in
 * place for the existing -1/<=2 returns.
 *
 * get_new_random_fd() itself has two distinct paths that can return
 * -1, both of which feed back into this outer regen loop:
 *   (1) the populated-provider list is empty — no providers are
 *       active, or every active provider's OBJ_GLOBAL pool is
 *       currently empty/broken; and
 *   (2) the inner per-attempt retry budget (10 rerolls) is exhausted
 *       because every draw from the chosen provider came back <=2
 *       (stdin/stdout/stderr or a transient provider-side -1).
 * The bound below has to guard against either source, not just (1).
 *
 * Without this bound, either of those -1 sources — or a persistently
 * untracked return from get_new_random_fd() — can tight-loop in
 * argument generation.  Because the syscall record is still in PREP
 * at that point, the parent's progress check (which only acts from
 * BEFORE onward) does not consider the child stuck and will not kill
 * it, so a single child can burn a CPU indefinitely.
 */
#define GET_RANDOM_FD_BUDGET 64

int get_random_fd(void)
{
	struct childdata *child = this_child();
	unsigned int retries = 0;
	unsigned int outer_retries = 0;

	/* During init (no child context), skip fd_lifetime caching. */
	if (child == NULL)
		return get_new_random_fd();

	/*
	 * If our cached fd's slot has been mutated since we cached it
	 * (close, reopen, or simply emptied) the slot's generation will
	 * differ from what we recorded.  A NULL lookup also counts as
	 * stale — the fd was removed from tracking.
	 */
	if (child->fd_lifetime > 0) {
		struct fd_hash_entry *e = fd_hash_lookup(child->current_fd);

		if (e == NULL ||
		    __atomic_load_n(&e->gen, __ATOMIC_ACQUIRE) !=
		    child->cached_fd_generation) {
			__atomic_add_fetch(&shm->stats.fd.stale_by_generation, 1,
					   __ATOMIC_RELAXED);
			child->fd_lifetime = 0;
		}
	}

	/* return the same fd as last time if we haven't over-used it yet. */
regen:
	{
		/*
		 * Once the outer has already churned through several passes
		 * without producing a usable fd, additional iterations at the
		 * full budget are unlikely to find new candidates — decay the
		 * effective bound so we bail out of the exhaustion cascade
		 * sooner instead of burning the full 64 sweeps.
		 */
		unsigned int effective_budget = GET_RANDOM_FD_BUDGET;

		if (outer_retries >= 4)
			effective_budget = GET_RANDOM_FD_BUDGET / 2;
		if (outer_retries >= 5)
			effective_budget = GET_RANDOM_FD_BUDGET / 4;

		if (outer_retries++ >= effective_budget) {
			__atomic_add_fetch(&shm->stats.fd.random_exhausted, 1,
					   __ATOMIC_RELAXED);
			outputerr("get_random_fd: outer retry budget (%u) exhausted, "
				  "returning -1\n", GET_RANDOM_FD_BUDGET);
			return -1;
		}
	}

	if (child->fd_lifetime == 0) {
		struct fd_hash_entry *e;

		child->current_fd = get_new_random_fd();

		/*
		 * get_new_random_fd() returns -1 only when every active
		 * provider's OBJ_GLOBAL pool is currently empty (or no
		 * providers are active).  Provider pools populate once at
		 * init via .init and only ever drain after that — no
		 * provider exposes a runtime .open replenish hook — so
		 * further outer iterations in this child will see the same
		 * state and burn the budget for no benefit.  Without this
		 * early-exit, every fd-arg syscall in a depleted-pool child
		 * spins the outer regen loop up to the decayed cap (16
		 * iterations under the existing decay), calls
		 * get_new_random_fd() each time only to get -1 again, and
		 * emits the post-budget "outer retry budget exhausted"
		 * outputerr — hundreds per child under sustained churn.
		 *
		 * Bail with the same exhaustion accounting the post-budget
		 * bail uses (same -1 contract to the caller, same EBADF
		 * surface in the kernel) but without the per-call log
		 * spam: when the pool is genuinely empty the message rate
		 * makes a healthy child indistinguishable from a stuck one
		 * and floods the bug log.  Persistent fd_random_exhausted
		 * remains the observable signal; the new pool-size dump in
		 * open_fds() makes the depletion timeline reproducible
		 * from a single run's log.
		 */
		if (child->current_fd < 0) {
			__atomic_add_fetch(&shm->stats.fd.random_exhausted, 1,
					   __ATOMIC_RELAXED);
			child->fd_lifetime = 0;
			return -1;
		}

		/*
		 * Cache the slot's generation so the next iteration can
		 * detect close-then-reopen-to-same-fd recycling without a
		 * syscall.  An untracked fd (e.g. a child-private fd not in
		 * the global pool) gets cached_fd_generation = 0; that won't
		 * match any real entry's gen, so the next iteration will
		 * always re-fetch.
		 */
		e = fd_hash_lookup(child->current_fd);
		if (e == NULL && child->current_fd >= 0 && retries++ < 10) {
			__atomic_add_fetch(&shm->stats.fd.stale_detected, 1,
					   __ATOMIC_RELAXED);
			goto regen;
		}
		child->cached_fd_generation = e ?
			__atomic_load_n(&e->gen, __ATOMIC_ACQUIRE) : 0;

		if (max_children >= 5)
			child->fd_lifetime = RAND_RANGE(5U, max_children);
		else
			child->fd_lifetime = RAND_RANGE(1, 5);
	} else
		child->fd_lifetime--;

	if (child->current_fd <= 2) {
		child->fd_lifetime = 0;
		goto regen;
	}

	return child->current_fd;
}

/*
 * Return an fd of a specific type for syscalls that expect a particular
 * kind of fd (epoll, timerfd, socket, etc.).  Falls back to get_random_fd()
 * if no objects of that type exist.
 *
 * Validates the fd is still tracked by the parent via the fd_hash
 * lookup — a missing entry means the fd was closed (in another child or
 * by a cleanup path) and the object snapshot we got is stale.
 */
int get_typed_fd(enum argtype type)
{
	struct object *obj;
	enum objecttype objtype;
	int fd;
	unsigned int retries = 0;

	switch (type) {
	case ARG_FD_BPF_BTF:	objtype = OBJ_FD_BPF_BTF; break;
	case ARG_FD_BPF_LINK:	objtype = OBJ_FD_BPF_LINK; break;
	case ARG_FD_BPF_MAP:	objtype = OBJ_FD_BPF_MAP; break;
	case ARG_FD_BPF_PROG:	objtype = OBJ_FD_BPF_PROG; break;
	case ARG_FD_EPOLL:	objtype = OBJ_FD_EPOLL; break;
	case ARG_FD_EVENTFD:	objtype = OBJ_FD_EVENTFD; break;
	case ARG_FD_FANOTIFY:	objtype = OBJ_FD_FANOTIFY; break;
	case ARG_FD_FS_CTX:	objtype = OBJ_FD_FS_CTX; break;
	case ARG_FD_INOTIFY:	objtype = OBJ_FD_INOTIFY; break;
	case ARG_FD_IO_URING:	objtype = OBJ_FD_IO_URING; break;
	case ARG_FD_LANDLOCK:	objtype = OBJ_FD_LANDLOCK; break;
	case ARG_FD_MEMFD:	objtype = OBJ_FD_MEMFD; break;
	case ARG_FD_MOUNT:	objtype = OBJ_FD_MOUNT; break;
	case ARG_FD_MQ:		objtype = OBJ_FD_MQ; break;
	case ARG_FD_PERF:	objtype = OBJ_FD_PERF; break;
	case ARG_FD_PIDFD:	objtype = OBJ_FD_PIDFD; break;
	case ARG_FD_PIPE:	objtype = OBJ_FD_PIPE; break;
	case ARG_FD_SIGNALFD:	objtype = OBJ_FD_SIGNALFD; break;
	case ARG_FD_SOCKET:	objtype = OBJ_FD_SOCKET; break;
	case ARG_FD_TIMERFD:	objtype = OBJ_FD_TIMERFD; break;
	default:
		return get_random_fd();
	}

retry:
	if (retries >= 10)
		return get_random_fd();

	obj = get_random_object(objtype, OBJ_GLOBAL);
	if (obj == NULL)
		return get_random_fd();

	if (!objpool_check(obj, objtype)) {
		retries++;
		goto retry;
	}

	/*
	 * Lazy-arm epoll fds in child context.  arm_epoll() invokes
	 * epoll_ctl(EPOLL_CTL_ADD) on a fuzzer-controlled target_fd
	 * whose ->poll handler can block indefinitely (e.g. /dev/fuse
	 * waiting on its userspace daemon).  Doing this from the
	 * parent's main loop wedges the whole session because the
	 * watchdog cannot kill the parent; doing it from a child is
	 * recoverable via is_child_making_progress().  See the block
	 * comment above arm_epoll() in fds/epoll.c.
	 */
	if (objtype == OBJ_FD_EPOLL)
		arm_epoll_if_needed(&obj->epollobj);

	fd = fd_from_object(obj, objtype);
	if (fd < 0)
		return get_random_fd();

	/* Don't hand out stdin/stdout/stderr to syscalls. */
	if (fd <= 2)
		return get_random_fd();

	/*
	 * Validate fd is still tracked in this child's snapshot of the
	 * fd_hash.  A miss means the fd was closed (in this child) and
	 * the snapshot is stale; fall through to another pick.
	 */
	if (fd_hash_lookup(fd) == NULL) {
		__atomic_add_fetch(&shm->stats.fd.stale_detected, 1, __ATOMIC_RELAXED);
		retries++;
		goto retry;
	}

	return fd;
}

/*
 * Pick a random fd from the subset of fd_types whose backing kernel
 * file ops actually park the caller on a real wait queue: pipes,
 * eventfd, timerfd, signalfd, inotify, fanotify, and sockets.  These
 * are the fd shapes whose ->poll handlers feed poll(2)/select(2)
 * properly, as opposed to regular-file fds (which short-circuit to
 * POLLIN | POLLOUT) or random untracked fds (which are predominantly
 * non-pollable or closed).
 *
 * Each candidate fd_type is filtered through get_typed_fd(), which
 * already skips empty provider pools and falls back to get_random_fd()
 * if no object of the requested fd_type is available — so even on a
 * minimal startup configuration this never wedges.  Providers tagged
 * poll_can_block are excluded by construction: none of the listed
 * fd_types opt into that tag (FUSE/uffd/kvm/io_uring/pidfd/seccomp_notif
 * are kept out so the wait/wake codepath in do_sys_poll / do_select
 * actually gets to block).
 */
int get_pollable_random_fd(void)
{
	static const enum argtype pollable[] = {
		ARG_FD_PIPE,
		ARG_FD_EVENTFD,
		ARG_FD_TIMERFD,
		ARG_FD_SIGNALFD,
		ARG_FD_INOTIFY,
		ARG_FD_FANOTIFY,
		ARG_FD_SOCKET,
	};

	return get_typed_fd(pollable[rnd_modulo_u32(ARRAY_SIZE(pollable))]);
}

/*
 * Return a live fd from this child's recent-returns ring, or -1 if none
 * are available.  Validates each candidate with fcntl(F_GETFD) and
 * evicts stale entries (EBADF) inline to keep the ring clean.
 */
int get_child_live_fd(struct childdata *child)
{
	struct child_fd_ring *ring = &child->live_fds;
	unsigned int i, retries;

	for (retries = 0; retries < CHILD_FD_RING_SIZE; retries++) {
		i = rnd_modulo_u32(CHILD_FD_RING_SIZE);
		int fd = ring->fds[i];

		if (fd <= 2)
			continue;

		if (fcntl(fd, F_GETFD) == -1 && errno == EBADF) {
			ring->fds[i] = -1;
			continue;
		}

		return fd;
	}

	return -1;
}
