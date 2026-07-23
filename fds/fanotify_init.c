/* fanotify FDs */

#include <errno.h>
#include <unistd.h>

#include "child.h"
#include "fd.h"
#include "syscall-gate.h"
#include "fanotify.h"
#include "objects.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define NR_FANOTIFYFDS 10

static int fanotify_init(__unused__ unsigned int flags, __unused__ unsigned int eflags)
{
#ifdef SYS_fanotify_init
	return trinity_raw_syscall(SYS_fanotify_init, flags, eflags);
#else
	return -ENOSYS;
#endif
}

/*
 * Cross-process safe: only reads obj->fanotifyobj scalar fields and the
 * scope scalar.  These survive fork/COW and no process-local pointers
 * are dereferenced, so it is correct to call this from a different
 * process than the one that allocated the obj.
 */
static void fanotifyfd_dump(struct object *obj, enum obj_scope scope)
{
	struct fanotifyobj *fo = &obj->fanotifyobj;

	output(2, "fanotify fd:%d flags:%x eventflags:%x scope:%d\n",
		fo->fd, fo->flags, fo->eventflags, scope);
}

static int open_fanotify_fd(void)
{
	struct object *obj;
	unsigned long flags, eventflags;
	int fd;

	eventflags = get_fanotify_init_event_flags();
	flags = get_fanotify_init_flags();
	fd = fanotify_init(flags, eventflags);
	if (fd < 0)
		return false;

	obj = alloc_object();
	if (obj == NULL) {
		close(fd);
		return false;
	}
	obj->fanotifyobj.fd = fd;
	obj->fanotifyobj.flags = flags;
	obj->fanotifyobj.eventflags = eventflags;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_FANOTIFY);
	return true;
}

static int init_fanotify_fds(void)
{
	struct objhead *head;
	unsigned int i;
	int ret = false;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_FANOTIFY);
	head->destroy = &close_fd_destructor;
	head->dump = &fanotifyfd_dump;
	/*
	 * fanotifyobj is {int fd; int flags; int eventflags;} with no
	 * pointer members, so the OBJ_GLOBAL pool's scalars stay valid
	 * across fork/COW and cross-process reads are safe.
	 */

	for (i = 0; i < NR_FANOTIFYFDS; i++) {
		if (open_fanotify_fd())
			ret = true;
	}

	return ret;
}

static int get_rand_fanotifyfd(void)
{
	if (objects_empty(OBJ_FD_FANOTIFY) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->fanotifyobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the fanotify fd routed into fanotify_mark()/read() via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_FANOTIFY, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_FANOTIFY))
			continue;

		fd = obj->fanotifyobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

/*
 * Periodic child-tick top-up.  See the block comment above
 * epoll_try_replenish() (fds/epoll.c) for the general contract.
 * init_fanotify_fds() seeds NR_FANOTIFYFDS entries once; without this
 * hook a child that drained its private copy stopped seeing an
 * ARG_FD_FANOTIFY hit at all.  Reuse the same randomised flag / event-
 * flag generators that init used so the topped-up fds carry the same
 * flag distribution rather than one fixed shape.
 */
static void fanotify_try_replenish(unsigned int budget)
{
	struct childdata *child = this_child();
	unsigned int i;
	/*
	 * See the block comment above memfd_try_replenish() (fds/memfd.c) for
	 * the rationale.  child_fd_ring_push() is a shared, pure-overwrite
	 * hint cache -- it does not own the fds it evicts.  Every fanotify fd
	 * we mint past live_fds's 16-slot window would leak for the child's
	 * life, so keep a per-child 32-slot ring of the fanotify fds WE
	 * created and close the one that ages out before reusing its slot.
	 */
	static int created_fds[32];
	static unsigned int created_head;

	if (child == NULL)
		return;

	for (i = 0; i < budget; i++) {
		unsigned long flags = get_fanotify_init_flags();
		unsigned long eventflags = get_fanotify_init_event_flags();
		int fd = fanotify_init(flags, eventflags);

		if (fd < 0)
			return;

		if (created_head >= ARRAY_SIZE(created_fds))
			close(created_fds[created_head % ARRAY_SIZE(created_fds)]);
		created_fds[created_head % ARRAY_SIZE(created_fds)] = fd;
		created_head++;

		child_fd_ring_push(&child->live_fds, fd);
	}
}

static const struct fd_provider fanotify_fd_provider = {
	.name = "fanotify",
	.objtype = OBJ_FD_FANOTIFY,
	.enabled = true,
	.init = &init_fanotify_fds,
	.get = &get_rand_fanotifyfd,
	.try_replenish = &fanotify_try_replenish,
};

REG_FD_PROV(fanotify_fd_provider);
