/* eventfd FDs */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>

#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"
#include "compat.h"

static void eventfd_destructor(struct object *obj)
{
	close(obj->eventfdobj.fd);
}

/*
 * Cross-process safe: only reads obj->eventfdobj fields (now in shm
 * via alloc_shared_obj) and the scope scalar.  No process-local
 * pointers are dereferenced, so it is correct to call this from a
 * different process than the one that allocated the obj — which
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
	head->destroy = &eventfd_destructor;
	head->dump = &eventfd_dump;
	head->shared_alloc = true;

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		struct object *obj;
		int fd;
		int count = rand32();

		fd = eventfd(count, flags[i]);
		if (fd < 0)
			continue;

		obj = alloc_shared_obj(sizeof(struct object));
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
	 * Versioned slot pick + validate_object_handle() before the
	 * obj->eventfdobj.fd deref, mirroring the wireup at 15b6257b8206
	 * (fds/sockets.c get_rand_socketinfo) and 5ef98298f6ad
	 * (syscalls/keyctl.c KEYCTL_WATCH_KEY).  Same OBJ_GLOBAL lockless-
	 * reader UAF window the framework commit a7fdbb97830c spelled out:
	 * between the lockless slot pick and the consumer's read of
	 * the eventfd handed to read/write/poll syscalls via the fd_provider .get callback,
	 * the parent can destroy the obj, free_shared_obj() returns the
	 * chunk to the shared-heap freelist, and a concurrent
	 * alloc_shared_obj() recycles it underneath us.
	 */
	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_EVENTFD, OBJ_GLOBAL,
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
			outputerr("get_rand_eventfd_fd: bogus obj %p in "
				  "OBJ_FD_EVENTFD pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_EVENTFD, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
			continue;

		fd = obj->eventfdobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static int open_eventfd_fd(void)
{
	struct object *obj;
	int fd, count, flags;

	count = rand32();
	flags = RAND_BOOL() ? EFD_NONBLOCK : 0;
	if (RAND_BOOL())
		flags |= EFD_CLOEXEC;
	if (RAND_BOOL())
		flags |= EFD_SEMAPHORE;

	fd = eventfd(count, flags);
	if (fd < 0)
		return false;

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(fd);
		return false;
	}
	obj->eventfdobj.fd = fd;
	obj->eventfdobj.count = count;
	obj->eventfdobj.flags = flags;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_EVENTFD);
	return true;
}

static const struct fd_provider eventfd_fd_provider = {
	.name = "eventfd",
	.objtype = OBJ_FD_EVENTFD,
	.enabled = true,
	.init = &init_eventfd_fds,
	.get = &get_rand_eventfd_fd,
	.open = &open_eventfd_fd,
};

REG_FD_PROV(eventfd_fd_provider);
