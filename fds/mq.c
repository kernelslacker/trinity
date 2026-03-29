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

static void mq_destructor(struct object *obj)
{
	close(obj->mqobj.fd);
	mq_unlink(obj->mqobj.name);
}

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

	obj = alloc_object();
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

	for (i = 0; i < 5; i++) {
		if (open_one_mq(i))
			ret = true;
	}

	return ret;
}

static int get_rand_mq_fd(void)
{
	struct object *obj;

	if (objects_empty(OBJ_FD_MQ) == true)
		return -1;

	obj = get_random_object(OBJ_FD_MQ, OBJ_GLOBAL);
	return obj->mqobj.fd;
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
