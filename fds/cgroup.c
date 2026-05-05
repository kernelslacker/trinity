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
	struct object *obj;

	if (objects_empty(OBJ_FD_CGROUP) == true)
		return -1;

	obj = get_random_object(OBJ_FD_CGROUP, OBJ_GLOBAL);
	if (obj == NULL)
		return -1;
	return obj->cgroupfdobj.fd;
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
