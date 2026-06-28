/* cgroup directory FDs (O_PATH on /sys/fs/cgroup subgroups). */

#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include "cgroup.h"
#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

#define CGROUP_ROOT		"/sys/fs/cgroup"
#define CGROUP_INIT_POOL	8

static int open_cgroup_dir(const char *path)
{
	return open(path, O_PATH | O_CLOEXEC | O_DIRECTORY);
}

static bool register_cgroup_fd(int fd)
{
	struct object *obj;

	obj = alloc_object();
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
	head->destroy = &close_fd_destructor;
	head->dump = &generic_fd_dump;

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
		return added > 0;

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
	return added > 0;
}

int get_rand_cgroup_fd(void)
{
	if (objects_empty(OBJ_FD_CGROUP) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->cgroupfdobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of the
	 * returned cgroup fd, the parent can destroy the obj; release_obj()
	 * zeroes the chunk and routes it through deferred-free, so the
	 * stale slot pointer can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_CGROUP, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_CGROUP))
			continue;

		fd = obj->cgroupfdobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider cgroup_fd_provider = {
	.name = "cgroup",
	.objtype = OBJ_FD_CGROUP,
	.enabled = true,
	.init = &init_cgroup_fds,
	.get = &get_rand_cgroup_fd,
};

REG_FD_PROV(cgroup_fd_provider);
