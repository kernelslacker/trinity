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
#include "utils.h"

#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
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
	if (obj->memfdobj.name != NULL) {
		free_shared_str(obj->memfdobj.name,
				strlen(obj->memfdobj.name) + 1);
		obj->memfdobj.name = NULL;
	}
	close(obj->memfdobj.fd);
}

/*
 * Cross-process safe: only reads obj->memfdobj fields, all of which
 * (including the name string) now live in shm via alloc_shared_obj /
 * alloc_shared_strdup.  No process-local pointers are dereferenced,
 * so this is correct to call from a different process than the one
 * that allocated the obj — which matters because head->dump runs
 * from dump_childdata() in the parent's crash diagnostics path even
 * when a child triggered the crash.
 */
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
	/*
	 * Route obj structs for this provider through the shared obj
	 * heap so post-fork regen via try_regenerate_fd() → open_memfd_fd
	 * produces obj structs that already-forked children can see.
	 * The name field is the second pointer hung off this obj — it
	 * goes through the shared string heap below.
	 */
	head->shared_alloc = true;

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

		obj = alloc_shared_obj(sizeof(struct object));
		if (obj == NULL) {
			close(fd);
			continue;
		}
		obj->memfdobj.fd = fd;
		obj->memfdobj.name = alloc_shared_strdup(namestr);
		if (obj->memfdobj.name == NULL) {
			close(fd);
			free_shared_obj(obj, sizeof(struct object));
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
	if (obj == NULL)
		return -1;
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

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(fd);
		return false;
	}
	obj->memfdobj.fd = fd;
	obj->memfdobj.name = alloc_shared_strdup("memfd");
	if (obj->memfdobj.name == NULL) {
		close(fd);
		free_shared_obj(obj, sizeof(struct object));
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
