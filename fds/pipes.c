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

static void pipefd_destructor(struct object *obj)
{
	close(obj->pipeobj.fd);
}

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

	obj = alloc_object();
	if (obj == NULL) {
		close(pipes[0]);
		close(pipes[1]);
		return;
	}
	obj->pipeobj.fd = pipes[0];
	obj->pipeobj.flags = flags;
	obj->pipeobj.reader = true;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_PIPE);

	obj = alloc_object();
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

	for (i = 0; i < 16; i++)
		open_pipe();

	return true;
}

int get_rand_pipe_fd(void)
{
	struct object *obj;

	obj = get_random_object(OBJ_FD_PIPE, OBJ_GLOBAL);

	if (obj == NULL)
		return -1;

	return obj->pipeobj.fd;
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
