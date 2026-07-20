/* epoll related fds */

#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <string.h>

#include "child.h"
#include "fd.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

#define MAX_EPOLL_FDS 10

static const uint32_t epoll_events[] = {
	EPOLLIN, EPOLLOUT, EPOLLRDHUP, EPOLLPRI,
	EPOLLET, EPOLLONESHOT,
};

/*
 * Register 1-3 random fds with the epoll instance so that
 * epoll_wait/epoll_pwait actually have something to monitor.
 *
 * MUST run in child context only.  epoll_ctl(EPOLL_CTL_ADD) invokes the
 * target fd's ->poll handler synchronously inside the kernel
 * (ep_item_poll → fops->poll), and a fuzzer-controlled target_fd from
 * get_random_fd() can name an fd whose ->poll blocks indefinitely
 * (e.g. /dev/fuse waiting on an unresponsive userspace daemon, an
 * io_uring fd, an empty eventfd in a non-O_NONBLOCK pattern, ...).
 * If the parent's main loop calls this and the syscall blocks, the
 * watchdog cannot kill the parent, children are never reaped, and the
 * whole session wedges.  Children that block here are recovered by
 * is_child_making_progress() in the watchdog.
 */
static void arm_epoll(int epfd)
{
	unsigned int i, count;

	count = 1 + rnd_modulo_u32(3);
	for (i = 0; i < count; i++) {
		struct epoll_event ev;
		int target_fd;
		unsigned int j, nbits;

		target_fd = get_random_fd();
		if (target_fd < 0)
			continue;

		/* Don't add an epoll fd to itself */
		if (target_fd == epfd)
			continue;

		/*
		 * Refuse fds whose owning fd_provider opted into
		 * poll_can_block.  ep_item_poll runs the target's f_op->poll
		 * synchronously inside EPOLL_CTL_ADD, and a blocking ->poll
		 * (FUSE without a daemon, idle io_uring CQ, vCPU not yet
		 * KVM_RUN'd, never-exiting pidfd target, unregistered uffd)
		 * parks the calling task in TASK_UNINTERRUPTIBLE on the
		 * per-fd waitqueue.  The watchdog cannot kill it and
		 * defer-slot-reuse pins the slot, cascading into the wedge
		 * captured at 2026-05-06 (117 children across the four
		 * ep_item_poll callsites: do_epoll_ctl+0x123b,
		 * ep_send_events+0x104, __ep_eventpoll_poll+0x123,
		 * ep_loop_check_proc+0x76).
		 */
		if (fd_poll_can_block(target_fd)) {
			__atomic_add_fetch(&shm->stats.epoll_volatility.blocking_poll_skipped, 1,
					   __ATOMIC_RELAXED);
			continue;
		}

		ev.events = 0;
		nbits = 1 + rnd_modulo_u32(ARRAY_SIZE(epoll_events));
		for (j = 0; j < nbits; j++)
			ev.events |= epoll_events[rnd_modulo_u32(ARRAY_SIZE(epoll_events))];
		ev.data.fd = target_fd;

		epoll_ctl(epfd, EPOLL_CTL_ADD, target_fd, &ev);
	}
}

/*
 * Per-process bitmap of "have I already armed this epfd?".  Lives in
 * BSS, so each forked child gets its own COW copy and the writes never
 * touch the OBJ_GLOBAL shm region.  Indexed by epollobj.pool_idx,
 * which the parent stamps once at alloc time.
 *
 * Per-process state is correct even though the same epfd may end up
 * armed independently by multiple children: EPOLL_CTL_ADD on an fd
 * already in the set returns -EEXIST, so the duplicate calls are
 * harmless and bounded (max_children × MAX_EPOLL_FDS over a session).
 */
static bool child_armed_epfds[MAX_EPOLL_FDS];

/*
 * Child-side lazy arm.  A child that wedges inside arm_epoll's
 * epoll_ctl is killable by the watchdog and replaced by a fresh fork —
 * the parent is never the one holding the syscall, which is the entire
 * point of deferring the arm.
 */
void arm_epoll_if_needed(struct epollobj *eo)
{
	unsigned int idx = eo->pool_idx;

	/* Defensive belt: pool_idx values >= MAX_EPOLL_FDS would over-index
	 * the per-process bitmap.  init_epoll_fds caps the pool at
	 * MAX_EPOLL_FDS and no post-fork producer adds more, so this never
	 * fires today — the check stays as insurance against future growth
	 * of next_pool_idx. */
	if (idx >= MAX_EPOLL_FDS)
		return;

	if (child_armed_epfds[idx])
		return;
	child_armed_epfds[idx] = true;

	arm_epoll(eo->fd);
	__atomic_add_fetch(&shm->stats.epoll_volatility.lazy_armed, 1,
			   __ATOMIC_RELAXED);
}

/*
 * Cross-process safe: only reads obj->epollobj scalar fields and the
 * scope scalar.  These survive fork/COW and no process-local pointers
 * are dereferenced, so it is correct to call this from a different
 * process than the one that allocated the obj — which
 * matters because head->dump runs from dump_childdata() in the
 * parent's crash diagnostics path even when a child triggered the
 * crash.
 */
static void epoll_dump(struct object *obj, enum obj_scope scope)
{
	struct epollobj *eo = &obj->epollobj;

	output(2, "epoll fd:%d used create1?:%d flags:%x pool_idx:%u scope:%d\n",
		eo->fd, eo->create1, eo->flags, eo->pool_idx, scope);
}

/*
 * Monotonically incremented for each epollobj allocated by this
 * provider (init pool + post-init regens).  Parent-only writer; lives
 * in the parent's BSS.
 * Stamped into eo->pool_idx so children can use it as a stable bitmap
 * key.  Values >= MAX_EPOLL_FDS are intentionally allowed and are
 * filtered by arm_epoll_if_needed()'s safety belt.
 */
static unsigned int next_pool_idx;

static int init_epoll_fds(void)
{
	struct object *obj;
	struct objhead *head;
	unsigned int i = 0;
	int fd, use_create1;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_EPOLL);
	head->destroy = &close_fd_destructor;
	head->dump = &epoll_dump;

	while (i < MAX_EPOLL_FDS) {
		use_create1 = RAND_BOOL();
		if (use_create1) {
			fd = epoll_create1(EPOLL_CLOEXEC);
		} else {
			fd = epoll_create(1);
			if (fd != -1)
				fcntl(fd, F_SETFD, FD_CLOEXEC);
		}

		if (fd == -1) {
			output(0, "init_epoll_fds fail: %s\n", strerror(errno));
			return false;
		}

		obj = alloc_object();
		if (obj == NULL) {
			close(fd);
			return false;
		}
		obj->epollobj.fd = fd;
		obj->epollobj.create1 = use_create1;
		obj->epollobj.flags = use_create1 ? EPOLL_CLOEXEC : 0;
		obj->epollobj.pool_idx = next_pool_idx++;
		add_object(obj, OBJ_GLOBAL, OBJ_FD_EPOLL);
		i++;
	}
	return true;
}

static int get_rand_epoll_fd(void)
{
	if (objects_empty(OBJ_FD_EPOLL) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->epollobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the epoll fd passed to epoll_ctl/epoll_wait via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_EPOLL, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_EPOLL))
			continue;

		fd = obj->epollobj.fd;
		if (fd < 0)
			continue;

		arm_epoll_if_needed(&obj->epollobj);

		return fd;
	}

	return -1;
}

/*
 * Periodic child-tick top-up.  init_epoll_fds() populates MAX_EPOLL_FDS
 * entries into the OBJ_GLOBAL pool once at startup; each child inherits
 * a copy that only drains from there.  Once the child's private copy
 * has been culled by close / dup2 / close_range hits the ARG_FD_EPOLL
 * pool goes empty and typed picks fall back to get_random_fd() -- so
 * arm_epoll_if_needed(), ep_item_poll exercise, and every epoll_ctl /
 * epoll_wait sanitiser that consults ARG_FD_EPOLL stops seeing an
 * epoll fd at all.
 *
 * child_fd_ring_push() reaches gen_arg_fd's 70% live-fd path directly.
 * add_object(OBJ_GLOBAL) from child context is a no-op by design (see
 * the mainpid guard in objects/registry.c), so this is the only
 * post-fork publish channel available to a provider without changing
 * the pool-ownership model.  The fd is CLOEXEC; whether the child
 * later hands it off to epoll_ctl or to a completely different
 * syscall via ARG_FD is up to arg-generation -- both are useful.
 */
static void epoll_try_replenish(unsigned int budget)
{
	struct childdata *child = this_child();
	unsigned int i;

	if (child == NULL)
		return;

	for (i = 0; i < budget; i++) {
		int fd = epoll_create1(EPOLL_CLOEXEC);

		if (fd < 0)
			return;
		child_fd_ring_push(&child->live_fds, fd);
	}
}

static const struct fd_provider epoll_fd_provider = {
	.name = "epoll",
	.objtype = OBJ_FD_EPOLL,
	.enabled = true,
	.init = &init_epoll_fds,
	.get = &get_rand_epoll_fd,
	.try_replenish = &epoll_try_replenish,
};

REG_FD_PROV(epoll_fd_provider);
