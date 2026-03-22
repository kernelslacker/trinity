/* landlock FD provider. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "fd.h"
#include "objects.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void landlock_destructor(struct object *obj)
{
	close(obj->landlockobj.fd);
}

static void landlock_dump(struct object *obj, bool global)
{
	output(2, "landlock fd:%d global:%d\n",
		obj->landlockobj.fd, global);
}

static int open_landlock_fd(void)
{
#ifdef __NR_landlock_create_ruleset
	struct object *obj;
	unsigned long long attr;
	int fd;

	attr = 0xfff;	/* LANDLOCK_ACCESS_FS_* bits */
	fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
	if (fd < 0)
		return false;

	obj = alloc_object();
	obj->landlockobj.fd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_LANDLOCK);
	return true;
#else
	return false;
#endif
}

static int init_landlock_fds(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_LANDLOCK);
	head->destroy = &landlock_destructor;
	head->dump = &landlock_dump;

	open_landlock_fd();

	return true;
}

static int get_rand_landlock_fd(void)
{
	struct object *obj;

	if (objects_empty(OBJ_FD_LANDLOCK) == true)
		return -1;

	obj = get_random_object(OBJ_FD_LANDLOCK, OBJ_GLOBAL);
	return obj->landlockobj.fd;
}

static const struct fd_provider landlock_fd_provider = {
	.name = "landlock",
	.objtype = OBJ_FD_LANDLOCK,
	.enabled = true,
	.init = &init_landlock_fds,
	.get = &get_rand_landlock_fd,
	.open = &open_landlock_fd,
};

REG_FD_PROV(landlock_fd_provider);
