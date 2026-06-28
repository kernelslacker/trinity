/* timerfd FDs */

#include <errno.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <string.h>

#include "fd.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"
#include "compat.h"

/*
 * Cross-process safe: only reads obj->timerfdobj scalar fields and the
 * scope scalar.  These survive fork/COW and no process-local pointers
 * are dereferenced, so it is correct to call this from a different
 * process than the one that allocated the obj — which matters because
 * head->dump runs from dump_childdata() in the parent's crash
 * diagnostics path even when a child triggered the crash.
 */
static void timerfd_dump(struct object *obj, enum obj_scope scope)
{
	struct timerfdobj *to = &obj->timerfdobj;

	output(2, "timerfd fd:%d clockid:%d flags:%x scope:%d\n", to->fd, to->clockid, to->flags, scope);
}

/*
 * Arm a timerfd with a random expiration so the kernel actually
 * processes timer events when this fd is used in read/poll/epoll.
 */
static void arm_timerfd(int fd)
{
	struct itimerspec its;

	memset(&its, 0, sizeof(its));

	switch (rnd_modulo_u32(4)) {
	case 0:
		/* One-shot, fires soon */
		its.it_value.tv_sec = 0;
		its.it_value.tv_nsec = 1 + rnd_modulo_u32(999999999);
		break;
	case 1:
		/* Repeating, short interval */
		its.it_value.tv_sec = 0;
		its.it_value.tv_nsec = 1000;
		its.it_interval.tv_sec = 0;
		its.it_interval.tv_nsec = 1000 + rnd_modulo_u32(999999);
		break;
	case 2:
		/* One-shot, fires in 1-5 seconds */
		its.it_value.tv_sec = 1 + rnd_modulo_u32(5);
		break;
	case 3:
		/* Repeating, 1 second interval */
		its.it_value.tv_sec = 1;
		its.it_interval.tv_sec = 1;
		break;
	}

	timerfd_settime(fd, 0, &its, NULL);
}

static int __init_timerfd_fds(int clockid)
{
	struct objhead *head;
	unsigned int i;
	unsigned int flags[] = {
		0,
		TFD_NONBLOCK,
		TFD_CLOEXEC,
		TFD_NONBLOCK | TFD_CLOEXEC,
	};

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_TIMERFD);
	head->destroy = &close_fd_destructor;
	head->dump = &timerfd_dump;
	/*
	 * timerfdobj is {int fd; int clockid; int flags;} — no pointer
	 * members — so the OBJ_GLOBAL pool's scalars stay valid across
	 * fork/COW and cross-process reads are safe.
	 */

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		struct object *obj;
		int fd;

		fd = timerfd_create(clockid, flags[i]);
		if (fd == -1) {
			if (errno == ENOSYS)
				return false;
			continue;
		}

		arm_timerfd(fd);

		obj = alloc_object();
		if (obj == NULL) {
			close(fd);
			continue;
		}
		obj->timerfdobj.fd = fd;
		obj->timerfdobj.clockid = clockid;
		obj->timerfdobj.flags = flags[i];
		add_object(obj, OBJ_GLOBAL, OBJ_FD_TIMERFD);
	}
	return true;
}

static int init_timerfd_fds(void)
{
	int ok = 0;

	ok |= __init_timerfd_fds(CLOCK_REALTIME);
	ok |= __init_timerfd_fds(CLOCK_MONOTONIC);
	ok |= __init_timerfd_fds(CLOCK_BOOTTIME);
	ok |= __init_timerfd_fds(CLOCK_REALTIME_ALARM);
	ok |= __init_timerfd_fds(CLOCK_BOOTTIME_ALARM);

	return ok;
}

static int get_rand_timerfd_fd(void)
{
	if (objects_empty(OBJ_FD_TIMERFD) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->timerfdobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the timerfd routed into timerfd_settime/gettime/read via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_TIMERFD, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_TIMERFD))
			continue;

		fd = obj->timerfdobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider timerfd_fd_provider = {
	.name = "timerfd",
	.objtype = OBJ_FD_TIMERFD,
	.enabled = true,
	.init = &init_timerfd_fds,
	.get = &get_rand_timerfd_fd,
};

REG_FD_PROV(timerfd_fd_provider);
