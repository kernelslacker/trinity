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
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Latched per-process: mq_open(3) consistently failed across the init
 * loop with an errno that won't change (ENOSYS = no CONFIG_POSIX_MQUEUE,
 * EOPNOTSUPP = filesystem refused the operation, ENOSPC = per-uid msg
 * queue limit hit and not getting any better since we never reach the
 * mq_unlink path on init failure).  Once latched, regen + consumers
 * fast-path past mq_open.  Mirrors the unsupported_<name> shape used by
 * kvm / landlock / memfd_secret.
 */
static bool unsupported_mq;

static void mq_destructor(struct object *obj)
{
	close(obj->mqobj.fd);
	mq_unlink(obj->mqobj.name);
}

/*
 * Cross-process safe: only reads obj->mqobj fields and the scope
 * scalar.  The scalars and the inline name[] array survive fork/COW
 * and no process-local pointers are dereferenced, so it is correct to
 * call this from a different process than the one that allocated the
 * obj — which matters because head->dump runs from dump_childdata() in
 * the parent's crash diagnostics path even when a child triggered the
 * crash.
 */
static void mq_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "mq fd:%d name:%s scope:%d\n",
		obj->mqobj.fd, obj->mqobj.name, scope);
}

static void make_mq_name(char *buf, size_t buflen, int idx)
{
	/* Include the pid so two trinity instances on the same host do
	 * not collide in the per-user POSIX mq namespace.  No modulo on
	 * idx: if the pool ever grows past 10 the names must still be
	 * unique. */
	snprintf(buf, buflen, "/trin%d_%d", (int)getpid(), idx);
}

static int open_one_mq(int idx)
{
	struct mq_attr attr;
	struct object *obj;
	char name[24];
	int fd;

	make_mq_name(name, sizeof(name), idx);

	memset(&attr, 0, sizeof(attr));
	attr.mq_maxmsg = 10;
	attr.mq_msgsize = 8192;

	fd = mq_open(name, O_RDWR | O_CREAT | O_NONBLOCK, 0600, &attr);
	if (fd < 0)
		return false;

	obj = alloc_object();
	if (obj == NULL) {
		mq_unlink(name);
		close(fd);
		return false;
	}
	obj->mqobj.fd = fd;
	memcpy(obj->mqobj.name, name, sizeof(name));
	obj->mqobj.attr_flags = attr.mq_flags;
	obj->mqobj.attr_maxmsg = attr.mq_maxmsg;
	obj->mqobj.attr_msgsize = attr.mq_msgsize;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_MQ);
	return true;
}

static int init_mq_fds(void)
{
	struct objhead *head;
	unsigned int i;
	int last_errno = 0;
	int ret = false;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_MQ);
	head->destroy = &mq_destructor;
	head->dump = &mq_dump;
	/*
	 * mqobj is {int fd; char name[N];} — the name is an inline char
	 * array stored in the obj struct itself, so it travels with the
	 * struct across fork/COW.  No separate shared string allocation is
	 * needed, and cross-process reads stay safe.
	 */

	for (i = 0; i < 5; i++) {
		if (open_one_mq(i))
			ret = true;
		else
			last_errno = errno;
	}

	if (!ret && (last_errno == ENOSYS || last_errno == EOPNOTSUPP ||
		     last_errno == ENOSPC)) {
		outputerr("init_mq_fds: all 5 mq_open attempts failed: %s -- latching unsupported_mq\n",
			strerror(last_errno));
		unsupported_mq = true;
	}

	return ret;
}

static int get_rand_mq_fd(void)
{
	if (unsupported_mq)
		return -1;

	if (objects_empty(OBJ_FD_MQ) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->mqobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the POSIX mqueue fd handed to mq_send/receive/notify via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_MQ, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_MQ))
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
};

REG_FD_PROV(mq_fd_provider);
