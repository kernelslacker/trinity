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
#include "udp.h"

static void pipefd_destructor(struct object *obj)
{
	close(obj->pipeobj.fd);
}

static void pipefd_dump(struct object *obj, bool global)
{
	struct pipeobj *po = &obj->pipeobj;
	struct msg_objcreatedpipe objmsg;

	output(2, "pipe fd:%d flags:%x [%s]\n",
		po->fd, po->flags,
		po->reader ? "reader" : "writer");

	init_msgobjhdr(&objmsg.hdr, OBJ_CREATED_PIPE, global, obj);
	objmsg.fd = po->fd;
	objmsg.flags = po->flags;
	objmsg.reader = po->reader;
	sendudp((char *) &objmsg, sizeof(objmsg));
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
	obj->pipeobj.fd = pipes[0];
	obj->pipeobj.flags = flags;
	obj->pipeobj.reader = TRUE;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_PIPE);

	obj = alloc_object();
	obj->pipeobj.fd = pipes[1];
	obj->pipeobj.flags = flags;
	obj->pipeobj.reader = FALSE;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_PIPE);
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

	return obj->pipeobj.fd;
}

static const struct fd_provider pipes_fd_provider = {
	.name = "pipes",
	.enabled = TRUE,
	.open = &open_pipes,
	.get = &get_rand_pipe_fd,
};

REG_FD_PROV(pipes_fd_provider);
