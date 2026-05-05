/* Pipe FD related functions. */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
	struct object *obj;
	int pipes[2];

	if (pipe2(pipes, flags) < 0) {
		perror("pipe fail.\n");
		return;
	}

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(pipes[0]);
		close(pipes[1]);
		return;
	}
	obj->pipeobj.fd = pipes[0];
	obj->pipeobj.flags = flags;
	obj->pipeobj.reader = true;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_PIPE);

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(pipes[1]);
		return;
	}
	obj->pipeobj.fd = pipes[1];
	obj->pipeobj.flags = flags;
	obj->pipeobj.reader = false;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_PIPE);
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
	head->shared_alloc = true;

	for (i = 0; i < 16; i++)
		open_pipe();

	return true;
}

int get_rand_pipe_fd(void)
{
	if (objects_empty(OBJ_FD_PIPE) == true)
		return -1;

	/*
	 * Versioned slot pick + validate_object_handle() before the
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
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_PIPE, OBJ_GLOBAL,
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
			outputerr("get_rand_pipe_fd: bogus obj %p in "
				  "OBJ_FD_PIPE pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_PIPE, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
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
	.open = NULL, /* pipe regeneration creates a pair (+2 fds) but only 1 was
		       * destroyed, leaking +1 fd per close/regenerate cycle */
};

REG_FD_PROV(pipes_fd_provider);
