/* Pipe FD related functions. */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "files.h"
#include "objects.h"
#include "pipes.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void pipefd_destructor(struct object *obj)
{
	close(obj->pipefd);
}

static void pipefd_dump(struct object *obj)
{
	output(0, "pipefd:%d\n", obj->pipefd);
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
	obj->pipefd = pipes[0];
	add_object(obj, OBJ_GLOBAL, OBJ_FD_PIPE);

	obj = alloc_object();
	obj->pipefd = pipes[1];
	add_object(obj, OBJ_GLOBAL, OBJ_FD_PIPE);

	output(2, "fd[%d] = pipe([reader] flags:%x)\n", pipes[0], flags);
	output(2, "fd[%d] = pipe([writer] flags:%x)\n", pipes[1], flags);
}


static int open_pipes(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_PIPE);
	head->destroy = &pipefd_destructor;
	head->dump = &pipefd_dump;

	open_pipe_pair(0);
	open_pipe_pair(O_NONBLOCK);
	open_pipe_pair(O_CLOEXEC);
	open_pipe_pair(O_NONBLOCK | O_CLOEXEC);

	return TRUE;
}

int get_rand_pipe_fd(void)
{
	struct object *obj;

	obj = get_random_object(OBJ_FD_PIPE, OBJ_GLOBAL);

	if (obj == NULL)
		return 0;

	return obj->pipefd;
}

static const struct fd_provider pipes_fd_provider = {
	.name = "pipes",
	.enabled = TRUE,
	.open = &open_pipes,
	.get = &get_rand_pipe_fd,
};

REG_FD_PROV(pipes_fd_provider);
