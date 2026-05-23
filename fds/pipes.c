/* Pipe FD related functions. */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "deferred-free.h"
#include "fd.h"
#include "objects.h"
#include "pipes.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void pipefd_destructor(struct object *obj)
{
	close(obj->pipeobj.fd);
}

/*
 * Cross-process safe: only reads obj->pipeobj fields (now in shm via
 * alloc_shared_obj) and the scope scalar.  No process-local pointers
 * are dereferenced, so calling this from a different process than the
 * allocator is correct — relevant because head->dump runs from
 * dump_childdata() in the parent's crash diagnostics path even when a
 * child triggered the crash.
 */
static void pipefd_dump(struct object *obj, enum obj_scope scope)
{
	struct pipeobj *po = &obj->pipeobj;

	output(2, "pipe fd:%d flags:%x [%s] scope:%d\n",
		po->fd, po->flags,
		po->reader ? "reader" : "writer",
		scope);
}

static void open_pipe_pair(unsigned int flags)
{
	struct object *robj, *wobj;
	int pipes[2];

	if (pipe2(pipes, flags) < 0) {
		perror("pipe fail.\n");
		return;
	}

	/*
	 * Allocate both objs before publishing either to the pool.  If we
	 * add the read end first and the second alloc_object() then fails,
	 * pipe[0] is left in the pool with no paired writer — consumers
	 * that clear O_NONBLOCK will block forever on the orphaned reader.
	 */
	robj = alloc_object();
	if (robj == NULL) {
		close(pipes[0]);
		close(pipes[1]);
		return;
	}

	wobj = alloc_object();
	if (wobj == NULL) {
		memset(robj, 0, sizeof(*robj));
		deferred_free_enqueue(robj);
		close(pipes[0]);
		close(pipes[1]);
		return;
	}

	robj->pipeobj.fd = pipes[0];
	robj->pipeobj.flags = flags;
	robj->pipeobj.reader = true;
	add_object(robj, OBJ_GLOBAL, OBJ_FD_PIPE);

	wobj->pipeobj.fd = pipes[1];
	wobj->pipeobj.flags = flags;
	wobj->pipeobj.reader = false;
	add_object(wobj, OBJ_GLOBAL, OBJ_FD_PIPE);
}


static int open_pipe(void)
{
	int flags;

	flags = RAND_BOOL() ? O_NONBLOCK : 0;
	if (RAND_BOOL())
		flags |= O_CLOEXEC;

	open_pipe_pair(flags);
	return true;
}

static int init_pipes(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_PIPE);
	head->destroy = &pipefd_destructor;
	head->dump = &pipefd_dump;
	/*
	 * Opt this provider into the shared obj heap.  __destroy_object()
	 * checks this flag to route the obj struct release through
	 * free_shared_obj() instead of free().
	 */

	for (i = 0; i < 16; i++)
		open_pipe();

	return true;
}

int get_rand_pipe_fd(void)
{
	if (objects_empty(OBJ_FD_PIPE) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->pipeobj.fd deref, mirroring the wireup at 15b6257b8206
	 * (fds/sockets.c get_rand_socketinfo) and 5ef98298f6ad
	 * (syscalls/keyctl.c KEYCTL_WATCH_KEY).  Same OBJ_GLOBAL lockless-
	 * reader UAF window the framework commit a7fdbb97830c spelled out:
	 * between the lockless slot pick and the consumer's read of
	 * the pipe fd routed into read/write/splice via the fd_provider .get callback,
	 * the parent can destroy the obj, free_shared_obj() returns the
	 * chunk to the shared-heap freelist, and a concurrent
	 * alloc_shared_obj() recycles it underneath us.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_PIPE, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_PIPE))
			continue;

		fd = obj->pipeobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider pipes_fd_provider = {
	.name = "pipes",
	.objtype = OBJ_FD_PIPE,
	.enabled = true,
	.init = &init_pipes,
	.get = &get_rand_pipe_fd,
};

REG_FD_PROV(pipes_fd_provider);
