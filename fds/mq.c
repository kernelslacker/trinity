/* POSIX message queue fd provider. */

#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void mq_destructor(struct object *obj)
{
	close(obj->mqobj.fd);
	mq_unlink(obj->mqobj.name);
}

/*
 * Cross-process safe: only reads obj->mqobj fields (now in shm via
 * alloc_shared_obj) and the scope scalar.  No process-local pointers
 * are dereferenced, so it is correct to call this from a different
 * process than the one that allocated the obj — which matters because
 * head->dump runs from dump_childdata() in the parent's crash
 * diagnostics path even when a child triggered the crash.
 */
static void mq_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "mq fd:%d name:%s scope:%d\n",
		obj->mqobj.fd, obj->mqobj.name, scope);
}

static void make_mq_name(char *buf, int idx)
{
	buf[0] = '/';
	buf[1] = 't';
	buf[2] = 'r';
	buf[3] = 'i';
	buf[4] = 'n';
	buf[5] = '0' + (idx % 10);
	buf[6] = '\0';
}

static int open_one_mq(int idx)
{
	struct mq_attr attr;
	struct object *obj;
	char name[8];
	int fd;

	make_mq_name(name, idx);

	memset(&attr, 0, sizeof(attr));
	attr.mq_maxmsg = 10;
	attr.mq_msgsize = 8192;

	fd = mq_open(name, O_RDWR | O_CREAT | O_NONBLOCK, 0600, &attr);
	if (fd < 0)
		return false;

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(fd);
		return false;
	}
	obj->mqobj.fd = fd;
	memcpy(obj->mqobj.name, name, sizeof(name));
	add_object(obj, OBJ_GLOBAL, OBJ_FD_MQ);
	return true;
}

static int open_mq_fd(void)
{
	return open_one_mq(rand() % 10);
}

static int init_mq_fds(void)
{
	struct objhead *head;
	unsigned int i;
	int ret = false;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_MQ);
	head->destroy = &mq_destructor;
	head->dump = &mq_dump;
	/*
	 * Opt this provider into the shared obj heap.  __destroy_object()
	 * checks this flag to route the obj struct release through
	 * free_shared_obj() instead of free().  mqobj is {int fd; char
	 * name[8];} — the name is an inline char array that lives in the
	 * obj struct itself, so it migrates to shm automatically with the
	 * rest of the struct.  No alloc_shared_str needed.
	 */
	head->shared_alloc = true;

	for (i = 0; i < 5; i++) {
		if (open_one_mq(i))
			ret = true;
	}

	return ret;
}

static int get_rand_mq_fd(void)
{
	if (objects_empty(OBJ_FD_MQ) == true)
		return -1;

	/*
	 * Versioned slot pick + validate_object_handle() before the
	 * obj->mqobj.fd deref, mirroring the wireup at 15b6257b8206
	 * (fds/sockets.c get_rand_socketinfo) and 5ef98298f6ad
	 * (syscalls/keyctl.c KEYCTL_WATCH_KEY).  Same OBJ_GLOBAL lockless-
	 * reader UAF window the framework commit a7fdbb97830c spelled out:
	 * between the lockless slot pick and the consumer's read of
	 * the POSIX mqueue fd handed to mq_send/receive/notify via the fd_provider .get callback,
	 * the parent can destroy the obj, free_shared_obj() returns the
	 * chunk to the shared-heap freelist, and a concurrent
	 * alloc_shared_obj() recycles it underneath us.
	 */
	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_MQ, OBJ_GLOBAL,
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
			outputerr("get_rand_mq_fd: bogus obj %p in "
				  "OBJ_FD_MQ pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_MQ, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
			continue;

		fd = obj->mqobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider mq_fd_provider = {
	.name = "mq",
	.objtype = OBJ_FD_MQ,
	.enabled = true,
	.init = &init_mq_fds,
	.get = &get_rand_mq_fd,
	.open = &open_mq_fd,
};

REG_FD_PROV(mq_fd_provider);
