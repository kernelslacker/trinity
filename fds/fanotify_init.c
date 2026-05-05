/* fanotify FDs */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "fanotify.h"
#include "objects.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"
#include "utils.h"

#define NR_FANOTIFYFDS 10

static int fanotify_init(__unused__ unsigned int flags, __unused__ unsigned int eflags)
{
#ifdef SYS_fanotify_init
	return syscall(SYS_fanotify_init, flags, eflags);
#else
	return -ENOSYS;
#endif
}

static void fanotifyfd_destructor(struct object *obj)
{
	close(obj->fanotifyobj.fd);
}

/*
 * Cross-process safe: only reads obj->fanotifyobj fields (now in shm
 * via alloc_shared_obj) and the scope scalar.  No process-local
 * pointers are dereferenced, so it is correct to call this from a
 * different process than the one that allocated the obj.
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

	obj = alloc_shared_obj(sizeof(struct object));
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
	head->destroy = &fanotifyfd_destructor;
	head->dump = &fanotifyfd_dump;
	/*
	 * Opt this provider into the shared obj heap.  __destroy_object()
	 * checks this flag to route the obj struct release through
	 * free_shared_obj() instead of free().  fanotifyobj is
	 * {int fd; int flags; int eventflags;} with no pointer members,
	 * so this is a mechanical conversion matching the pidfd template.
	 */
	head->shared_alloc = true;

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
	 * Versioned slot pick + validate_object_handle() before the
	 * obj->fanotifyobj.fd deref, mirroring the wireup at 15b6257b8206
	 * (fds/sockets.c get_rand_socketinfo) and 5ef98298f6ad
	 * (syscalls/keyctl.c KEYCTL_WATCH_KEY).  Same OBJ_GLOBAL lockless-
	 * reader UAF window the framework commit a7fdbb97830c spelled out:
	 * between the lockless slot pick and the consumer's read of
	 * the fanotify fd routed into fanotify_mark()/read() via the fd_provider .get callback,
	 * the parent can destroy the obj, free_shared_obj() returns the
	 * chunk to the shared-heap freelist, and a concurrent
	 * alloc_shared_obj() recycles it underneath us.
	 */
	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_FANOTIFY, OBJ_GLOBAL,
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
			outputerr("get_rand_fanotifyfd: bogus obj %p in "
				  "OBJ_FD_FANOTIFY pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_FANOTIFY, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
			continue;

		fd = obj->fanotifyobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider fanotify_fd_provider = {
	.name = "fanotify",
	.objtype = OBJ_FD_FANOTIFY,
	.enabled = true,
	.init = &init_fanotify_fds,
	.get = &get_rand_fanotifyfd,
	.open = &open_fanotify_fd,
};

REG_FD_PROV(fanotify_fd_provider);
