/* memfd FDs */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "fd.h"
#include "memfd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"

#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif

#ifndef USE_MEMFD_CREATE

static int memfd_create(__unused__ const char *uname, __unused__ unsigned int flag)
{
#ifdef SYS_memfd_create
	return syscall(SYS_memfd_create, uname, flag);
#else
	return -ENOSYS;
#endif
}
#endif

static void arm_memfd(int fd)
{
	static const unsigned int seal_flags[] = {
		F_SEAL_SEAL,
		F_SEAL_SHRINK,
		F_SEAL_GROW,
		F_SEAL_WRITE,
		F_SEAL_FUTURE_WRITE,
	};
	unsigned int seals = 0;
	unsigned int i, count;

	count = 1 + (rand() % 3);
	for (i = 0; i < count; i++)
		seals |= seal_flags[rand() % ARRAY_SIZE(seal_flags)];

	fcntl(fd, F_ADD_SEALS, seals);
}

static void memfd_destructor(struct object *obj)
{
	free(obj->memfdobj.name);
	obj->memfdobj.name = NULL;
	close(obj->memfdobj.fd);
}

static void memfd_dump(struct object *obj, enum obj_scope scope)
{
	struct memfdobj *mo = &obj->memfdobj;

	output(2, "memfd fd:%d name:%s flags:%x scope:%d\n",
		mo->fd, mo->name, mo->flags, scope);
}

static int init_memfd_fds(void)
{
	struct objhead *head;
	unsigned int i;
	unsigned int flags[] = {
		0,
		MFD_CLOEXEC,
		MFD_CLOEXEC | MFD_ALLOW_SEALING,
		MFD_ALLOW_SEALING, MFD_HUGETLB,
		MFD_NOEXEC_SEAL,
		MFD_EXEC,
	};

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_MEMFD);
	head->destroy = &memfd_destructor;
	head->dump = &memfd_dump;

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		struct object *obj;
		char namestr[] = "memfdN";
		int fd;

		snprintf(namestr, sizeof(namestr), "memfd%u", i + 1);

		fd = memfd_create(namestr, flags[i]);
		if (fd < 0)
			continue;

		if (flags[i] & MFD_ALLOW_SEALING)
			arm_memfd(fd);

		obj = alloc_object();
		obj->memfdobj.fd = fd;
		obj->memfdobj.name = strdup(namestr);
		if (!obj->memfdobj.name) {
			close(fd);
			free(obj);
			continue;
		}
		obj->memfdobj.flags = flags[i];
		add_object(obj, OBJ_GLOBAL, OBJ_FD_MEMFD);
	}

	return true;
}

static int get_rand_memfd_fd(void)
{
	struct object *obj;

	/* check if memfd unavailable/disabled. */
	if (objects_empty(OBJ_FD_MEMFD) == true)
		return -1;

	obj = get_random_object(OBJ_FD_MEMFD, OBJ_GLOBAL);
	return obj->memfdobj.fd;
}

static int open_memfd_fd(void)
{
	struct object *obj;
	int fd, flags;

	flags = RAND_BOOL() ? MFD_CLOEXEC : 0;
	if (RAND_BOOL())
		flags |= MFD_ALLOW_SEALING;

	fd = memfd_create("memfd", flags);
	if (fd < 0)
		return false;

	if (flags & MFD_ALLOW_SEALING)
		arm_memfd(fd);

	obj = alloc_object();
	obj->memfdobj.fd = fd;
	obj->memfdobj.name = strdup("memfd");
	if (!obj->memfdobj.name) {
		close(fd);
		free(obj);
		return false;
	}
	obj->memfdobj.flags = flags;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_MEMFD);
	return true;
}

static const struct fd_provider memfd_fd_provider = {
	.name = "memfd",
	.objtype = OBJ_FD_MEMFD,
	.enabled = true,
	.init = &init_memfd_fds,
	.get = &get_rand_memfd_fd,
	.open = &open_memfd_fd,
};

REG_FD_PROV(memfd_fd_provider);
