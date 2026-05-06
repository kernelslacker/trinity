/* epoll related fds */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "fd.h"
#include "objects.h"
#include "random.h"
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

	count = 1 + (rand() % 3);
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

		ev.events = 0;
		nbits = 1 + (rand() % ARRAY_SIZE(epoll_events));
		for (j = 0; j < nbits; j++)
			ev.events |= epoll_events[rand() % ARRAY_SIZE(epoll_events)];
		ev.data.fd = target_fd;

		epoll_ctl(epfd, EPOLL_CTL_ADD, target_fd, &ev);
	}
}

/*
 * Per-process bitmap of "have I already armed this epfd?".  Lives in
 * BSS, so each forked child gets its own COW copy and the writes never
 * touch the OBJ_GLOBAL shm region (which freeze_global_objects() has
 * mprotected PROT_READ before fork).  Indexed by epollobj.pool_idx,
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

	/* pool_idx beyond the bitmap can occur if the post-freeze regen
	 * path (open_epoll_fd via try_regenerate_fd) churns more epfds
	 * across a session than the initial pool size.  Skip rather
	 * than over-index — the regen'd epfd then plays as an empty
	 * epoll set in this consumer, which is benign (epoll_wait
	 * returns 0 / EAGAIN) and far better than a wild bitmap write. */
	if (idx >= MAX_EPOLL_FDS)
		return;

	if (child_armed_epfds[idx])
		return;
	child_armed_epfds[idx] = true;

	arm_epoll(eo->fd);
	__atomic_add_fetch(&shm->stats.epoll_lazy_armed, 1,
			   __ATOMIC_RELAXED);
}

static void epoll_destructor(struct object *obj)
{
	close(obj->epollobj.fd);
}

/*
 * Cross-process safe: only reads obj->epollobj fields (now in shm
 * via alloc_shared_obj) and the scope scalar.  No process-local
 * pointers are dereferenced, so it is correct to call this from a
 * different process than the one that allocated the obj — which
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
 * in the parent's BSS so freeze_global_objects() doesn't cover it.
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
	head->destroy = &epoll_destructor;
	head->dump = &epoll_dump;
	head->shared_alloc = true;

	while (i < MAX_EPOLL_FDS) {
		use_create1 = RAND_BOOL();
		if (use_create1)
			fd = epoll_create1(EPOLL_CLOEXEC);
		else
			fd = epoll_create(1);

		if (fd == -1) {
			output(0, "init_epoll_fds fail: %s\n", strerror(errno));
			return false;
		}

		obj = alloc_shared_obj(sizeof(struct object));
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

static int open_epoll_fd(void)
{
	struct object *obj;
	int fd, use_create1;

	use_create1 = RAND_BOOL();
	if (use_create1)
		fd = epoll_create1(EPOLL_CLOEXEC);
	else
		fd = epoll_create(1);

	if (fd == -1)
		return false;

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(fd);
		return false;
	}
	obj->epollobj.fd = fd;
	obj->epollobj.create1 = use_create1;
	obj->epollobj.flags = use_create1 ? EPOLL_CLOEXEC : 0;
	obj->epollobj.pool_idx = next_pool_idx++;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_EPOLL);
	return true;
}

static int get_rand_epoll_fd(void)
{
	if (objects_empty(OBJ_FD_EPOLL) == true)
		return -1;

	/*
	 * Versioned slot pick + validate_object_handle() before the
	 * obj->epollobj.fd deref, mirroring the wireup at 15b6257b8206
	 * (fds/sockets.c get_rand_socketinfo) and 5ef98298f6ad
	 * (syscalls/keyctl.c KEYCTL_WATCH_KEY).  Same OBJ_GLOBAL lockless-
	 * reader UAF window the framework commit a7fdbb97830c spelled out:
	 * between the lockless slot pick and the consumer's read of
	 * the epoll fd passed to epoll_ctl/epoll_wait via the fd_provider .get callback,
	 * the parent can destroy the obj, free_shared_obj() returns the
	 * chunk to the shared-heap freelist, and a concurrent
	 * alloc_shared_obj() recycles it underneath us.
	 */
	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_EPOLL, OBJ_GLOBAL,
						  &slot_idx, &slot_version);
		if (obj == NULL)
			continue;

		/*
		 * Heap pointers land at >= 0x10000 and below the 47-bit
		 * user/kernel boundary; anything outside that window can't
		 * be a real obj struct.  Reject before deref.
		 */
		if ((uintptr_t)obj < 0x10000UL ||
		    (uintptr_t)obj >= 0x800000000000UL) {
			outputerr("get_rand_epoll_fd: bogus obj %p in "
				  "OBJ_FD_EPOLL pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_EPOLL, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
			continue;

		fd = obj->epollobj.fd;
		if (fd < 0)
			continue;

		arm_epoll_if_needed(&obj->epollobj);

		return fd;
	}

	return -1;
}

static const struct fd_provider epoll_fd_provider = {
	.name = "epoll",
	.objtype = OBJ_FD_EPOLL,
	.enabled = true,
	.init = &init_epoll_fds,
	.get = &get_rand_epoll_fd,
	.open = &open_epoll_fd,
};

REG_FD_PROV(epoll_fd_provider);
