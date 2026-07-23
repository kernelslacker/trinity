/* inotify related fds */

#include <errno.h>
#include <unistd.h>
#include <sys/inotify.h>

#include "child.h"
#include "fd.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

static const char *watch_paths[] = {
	"/tmp", "/proc", "/sys", "/dev", "/dev/shm",
};

static const uint32_t watch_masks[] = {
	IN_ACCESS, IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE,
	IN_CLOSE_NOWRITE, IN_OPEN, IN_MOVED_FROM, IN_MOVED_TO,
	IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_MOVE_SELF,
	IN_ALL_EVENTS,
};

/*
 * Add 1-3 random watches so the kernel actually has something
 * to monitor and can generate events on this inotify fd.
 */
static void arm_inotify(int fd)
{
	unsigned int i, count;

	count = 1 + rnd_modulo_u32(3);
	for (i = 0; i < count; i++) {
		const char *path = watch_paths[rnd_modulo_u32(ARRAY_SIZE(watch_paths))];
		uint32_t mask = watch_masks[rnd_modulo_u32(ARRAY_SIZE(watch_masks))];

		/* OR in a second mask bit half the time */
		if (RAND_BOOL())
			mask |= watch_masks[rnd_modulo_u32(ARRAY_SIZE(watch_masks))];

		inotify_add_watch(fd, path, mask);
	}
}

/*
 * Cross-process safe: only reads obj->inotifyobj scalar fields and the
 * scope scalar.  These survive fork/COW and no process-local pointers
 * are dereferenced, so it is correct to call this from a different
 * process than the one that allocated the obj — which
 * matters because head->dump runs from dump_childdata() in the
 * parent's crash diagnostics path even when a child triggered the
 * crash.
 */
static void inotify_dump(struct object *obj, enum obj_scope scope)
{
	struct inotifyobj *io = &obj->inotifyobj;

	output(2, "inotify fd:%d flags:%x scope:%d\n", io->fd, io->flags, scope);
}

static int init_inotify_fds(void)
{
	struct objhead *head;
	struct object *obj;
	unsigned int i;
	int fd;
	int flags[] = {
		0,
		IN_NONBLOCK,
		IN_CLOEXEC,
		IN_NONBLOCK | IN_CLOEXEC,
	};

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_INOTIFY);
	head->destroy = &close_fd_destructor;
	head->dump = &inotify_dump;
	/*
	 * inotifyobj is {int fd; int flags;} with no pointer members, so
	 * the OBJ_GLOBAL pool's scalars stay valid across fork/COW and
	 * cross-process reads are safe.
	 */

	fd = inotify_init();
	if (fd < 0)
		fd = inotify_init1(0);
	if (fd < 0)
		return false;

	obj = alloc_object();
	if (obj == NULL) {
		close(fd);
		return false;
	}
	arm_inotify(fd);
	obj->inotifyobj.fd = fd;
	obj->inotifyobj.flags = 0;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_INOTIFY);

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		fd = inotify_init1(flags[i]);
		if (fd < 0)
			continue;

		obj = alloc_object();
		if (obj == NULL) {
			close(fd);
			continue;
		}
		arm_inotify(fd);
		obj->inotifyobj.fd = fd;
		obj->inotifyobj.flags = flags[i];
		add_object(obj, OBJ_GLOBAL, OBJ_FD_INOTIFY);
	}

	return true;
}

static int get_rand_inotify_fd(void)
{
	if (objects_empty(OBJ_FD_INOTIFY) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->inotifyobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the inotify fd consumed by inotify_add_watch / read via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_INOTIFY, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_INOTIFY))
			continue;

		fd = obj->inotifyobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

/*
 * Periodic child-tick top-up.  init_inotify_fds() populates the
 * OBJ_GLOBAL pool once at startup; each child inherits a copy that
 * only drains via close / dup2 / close_range hits.  Once the child's
 * private view is empty, get_rand_inotify_fd() and every ARG_FD_INOTIFY
 * consumer stops seeing an inotify fd at all.
 *
 * child_fd_ring_push() reaches gen_arg_fd's 70% live-fd path directly.
 * add_object(OBJ_GLOBAL) from child context is a no-op by design (see
 * the mainpid guard in objects/registry.c), so this is the only
 * post-fork publish channel available without changing the
 * pool-ownership model.  Reuse the CLOEXEC-marked subset of the
 * init_inotify_fds() flag set -- these fds may end up passed to
 * unrelated syscalls via ARG_FD, and CLOEXEC keeps them from leaking
 * across an exec.
 */
static void inotify_try_replenish(unsigned int budget)
{
	static const int flags[] = {
		IN_CLOEXEC,
		IN_NONBLOCK | IN_CLOEXEC,
	};
	struct childdata *child = this_child();
	unsigned int i;
	/*
	 * See the block comment above memfd_try_replenish() (fds/memfd.c) for
	 * the rationale.  child_fd_ring_push() is a shared, pure-overwrite
	 * hint cache -- it does not own the fds it evicts.  Every inotify fd
	 * we mint past live_fds's 16-slot window would leak for the child's
	 * life, so keep a per-child 32-slot ring of the inotify fds WE
	 * created and close the one that ages out before reusing its slot.
	 */
	static int created_fds[32];
	static unsigned int created_head;

	if (child == NULL)
		return;

	for (i = 0; i < budget; i++) {
		int fd = inotify_init1(flags[rnd_modulo_u32(ARRAY_SIZE(flags))]);

		if (fd < 0)
			return;

		if (created_head >= ARRAY_SIZE(created_fds))
			close(created_fds[created_head % ARRAY_SIZE(created_fds)]);
		created_fds[created_head % ARRAY_SIZE(created_fds)] = fd;
		created_head++;

		child_fd_ring_push(&child->live_fds, fd);
	}
}

static const struct fd_provider inotify_fd_provider = {
	.name = "inotify",
	.objtype = OBJ_FD_INOTIFY,
	.enabled = true,
	.init = &init_inotify_fds,
	.get = &get_rand_inotify_fd,
	.try_replenish = &inotify_try_replenish,
};

REG_FD_PROV(inotify_fd_provider);
