/* cgroup directory FDs (O_PATH on /sys/fs/cgroup subgroups). */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cgroup.h"
#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

#define CGROUP_ROOT		"/sys/fs/cgroup"
#define CGROUP_INIT_POOL	8

static void cgroup_destructor(struct object *obj)
{
	close(obj->cgroupfdobj.fd);
}

static void cgroup_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "cgroup fd:%d scope:%d\n", obj->cgroupfdobj.fd, scope);
}

static int open_cgroup_dir(const char *path)
{
	return open(path, O_PATH | O_CLOEXEC | O_DIRECTORY);
}

static bool register_cgroup_fd(int fd)
{
	struct object *obj;

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(fd);
		return false;
	}
	obj->cgroupfdobj.fd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_CGROUP);
	return true;
}

static int init_cgroup_fds(void)
{
	struct objhead *head;
	struct dirent *entry;
	unsigned int added = 0;
	DIR *dir;
	int fd;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_CGROUP);
	head->destroy = &cgroup_destructor;
	head->dump = &cgroup_dump;
	head->shared_alloc = true;

	/* Always register the root itself first; it's the one cgroup dir
	 * we're certain exists if /sys/fs/cgroup is mounted at all. */
	fd = open_cgroup_dir(CGROUP_ROOT);
	if (fd >= 0) {
		if (register_cgroup_fd(fd) == false)
			return false;
		added++;
	}

	dir = opendir(CGROUP_ROOT);
	if (dir == NULL)
		return true;

	while (added < CGROUP_INIT_POOL) {
		char path[PATH_MAX];
		struct stat st;

		entry = readdir(dir);
		if (entry == NULL)
			break;
		if (strcmp(entry->d_name, ".") == 0)
			continue;
		if (strcmp(entry->d_name, "..") == 0)
			continue;

		if (snprintf(path, sizeof(path), "%s/%s",
			     CGROUP_ROOT, entry->d_name) >= (int)sizeof(path))
			continue;

		/* Skip non-directories (cgroup.procs, cpu.stat, ...). */
		if (lstat(path, &st) < 0)
			continue;
		if (!S_ISDIR(st.st_mode))
			continue;

		fd = open_cgroup_dir(path);
		if (fd < 0)
			continue;

		if (register_cgroup_fd(fd) == false) {
			closedir(dir);
			return false;
		}
		added++;
	}

	closedir(dir);
	return true;
}

int get_rand_cgroup_fd(void)
{
	if (objects_empty(OBJ_FD_CGROUP) == true)
		return -1;

	/*
	 * Versioned slot pick + validate_object_handle() before the
	 * obj->cgroupfdobj.fd deref, mirroring the wireup at 15b6257b8206
	 * (fds/sockets.c get_rand_socketinfo) and 5ef98298f6ad
	 * (syscalls/keyctl.c KEYCTL_WATCH_KEY).  Same OBJ_GLOBAL lockless-
	 * reader UAF window the framework commit a7fdbb97830c spelled out:
	 * between the lockless slot pick and the consumer's read of the
	 * returned cgroup fd, the parent can destroy the obj,
	 * free_shared_obj() returns the chunk to the shared-heap freelist,
	 * and a concurrent alloc_shared_obj() recycles it underneath us.
	 */
	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_CGROUP, OBJ_GLOBAL,
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
			outputerr("get_rand_cgroup_fd: bogus obj %p in "
				  "OBJ_FD_CGROUP pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_CGROUP, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
			continue;

		fd = obj->cgroupfdobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static int open_cgroup_fd(void)
{
	int fd;

	fd = open_cgroup_dir(CGROUP_ROOT);
	if (fd < 0)
		return false;

	return register_cgroup_fd(fd) ? true : false;
}

static const struct fd_provider cgroup_fd_provider = {
	.name = "cgroup",
	.objtype = OBJ_FD_CGROUP,
	.enabled = true,
	.init = &init_cgroup_fds,
	.get = &get_rand_cgroup_fd,
	.open = &open_cgroup_fd,
};

REG_FD_PROV(cgroup_fd_provider);
