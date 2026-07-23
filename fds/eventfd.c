/* eventfd FDs */

#include <errno.h>
#include <unistd.h>
#include <sys/eventfd.h>

#include "child.h"
#include "fd.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

#include "kernel/eventfd.h"
/*
 * Cross-process safe: only reads obj->eventfdobj scalar fields and the
 * scope scalar.  These survive fork/COW and no process-local pointers
 * are dereferenced, so it is correct to call this from a different
 * process than the one that allocated the obj — which
 * matters because head->dump runs from dump_childdata() in the
 * parent's crash diagnostics path even when a child triggered the
 * crash.
 */
static void eventfd_dump(struct object *obj, enum obj_scope scope)
{
	struct eventfdobj *eo = &obj->eventfdobj;

	output(2, "eventfd fd:%d count:%d flags:%x scope:%d\n",
		eo->fd, eo->count, eo->flags, scope);
}

static int init_eventfd_fds(void)
{
	struct objhead *head;
	unsigned int i;
	const unsigned int flags[] = {
		0,
		EFD_NONBLOCK,
		EFD_NONBLOCK | EFD_SEMAPHORE,
		EFD_CLOEXEC,
		EFD_CLOEXEC  | EFD_NONBLOCK,
		EFD_CLOEXEC  | EFD_SEMAPHORE,
		EFD_CLOEXEC  | EFD_NONBLOCK | EFD_SEMAPHORE,
		EFD_SEMAPHORE,
	};

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_EVENTFD);
	head->destroy = &close_fd_destructor;
	head->dump = &eventfd_dump;

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		struct object *obj;
		int fd;
		int count = rnd_u32();

		fd = eventfd(count, flags[i]);
		if (fd < 0)
			continue;

		obj = alloc_object();
		if (obj == NULL) {
			close(fd);
			return false;
		}
		obj->eventfdobj.fd = fd;
		obj->eventfdobj.count = count;
		obj->eventfdobj.flags = flags[i];
		add_object(obj, OBJ_GLOBAL, OBJ_FD_EVENTFD);
	}

	return true;
}

static int get_rand_eventfd_fd(void)
{
	if (objects_empty(OBJ_FD_EVENTFD) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->eventfdobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the eventfd handed to read/write/poll syscalls via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_EVENTFD, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_EVENTFD))
			continue;

		fd = obj->eventfdobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

/*
 * Periodic child-tick top-up.  See the block comment above
 * epoll_try_replenish() for the general contract.  init_eventfd_fds()
 * seeds 8 entries once; a child that has closed most of them via
 * fuzz-driven close/dup2 hits stops seeing ARG_FD_EVENTFD picks.
 * Pushing fresh eventfds into the live-fd ring restores gen_arg_fd()
 * hits without touching the OBJ_GLOBAL pool the parent owns.
 *
 * Flags randomised across the same 3-bit set init_eventfd_fds() uses
 * so downstream read/write/poll paths see the semaphore vs. counter
 * split and the O_NONBLOCK vs. blocking split rather than one fixed
 * flavour.  The initial count is intentionally left at 0 to keep the
 * replenished fds cheap to close down again at process exit -- the
 * kernel-side benefit here is reachability, not the specific counter
 * value.
 */
static void eventfd_try_replenish(unsigned int budget)
{
	struct childdata *child = this_child();
	unsigned int i;
	static const unsigned int flags[] = {
		EFD_CLOEXEC,
		EFD_CLOEXEC | EFD_NONBLOCK,
		EFD_CLOEXEC | EFD_SEMAPHORE,
		EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE,
	};
	/*
	 * See the block comment above memfd_try_replenish() (fds/memfd.c) for
	 * the rationale.  child_fd_ring_push() is a shared, pure-overwrite
	 * hint cache -- it does not own the fds it evicts.  Every eventfd
	 * we mint past live_fds's 16-slot window would leak for the child's
	 * life, so keep a per-child 32-slot ring of the eventfds WE created
	 * and close the one that ages out before reusing its slot.
	 */
	static int created_fds[32];
	static unsigned int created_head;

	if (child == NULL)
		return;

	for (i = 0; i < budget; i++) {
		int fd = eventfd(0, flags[rnd_modulo_u32(ARRAY_SIZE(flags))]);

		if (fd < 0)
			return;

		if (created_head >= ARRAY_SIZE(created_fds))
			close(created_fds[created_head % ARRAY_SIZE(created_fds)]);
		created_fds[created_head % ARRAY_SIZE(created_fds)] = fd;
		created_head++;

		child_fd_ring_push(&child->live_fds, fd);
	}
}

static const struct fd_provider eventfd_fd_provider = {
	.name = "eventfd",
	.objtype = OBJ_FD_EVENTFD,
	.enabled = true,
	.init = &init_eventfd_fds,
	.get = &get_rand_eventfd_fd,
	.try_replenish = &eventfd_try_replenish,
};

REG_FD_PROV(eventfd_fd_provider);
