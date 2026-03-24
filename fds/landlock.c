/* landlock FD provider. */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/landlock.h>

#include "fd.h"
#include "objects.h"
#include "random.h"
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

static const char *landlock_paths[] = {
	"/tmp", "/dev", "/proc", "/sys", "/dev/shm",
};

/*
 * Add a few path-beneath rules to the landlock ruleset so it
 * has actual content. Without rules, the ruleset is an empty
 * shell and landlock_restrict_self is a no-op.
 *
 * We deliberately do NOT call landlock_restrict_self here —
 * that would sandbox the fuzzer itself. We just populate the
 * ruleset so that syscalls operating on it exercise real kernel paths.
 */
static void arm_landlock(int ruleset_fd)
{
#ifdef __NR_landlock_add_rule
	unsigned int i, count;

	count = 1 + (rand() % 3);
	for (i = 0; i < count; i++) {
		struct landlock_path_beneath_attr attr;
		const char *path;
		int path_fd;

		path = landlock_paths[rand() % ARRAY_SIZE(landlock_paths)];
		path_fd = open(path, O_PATH | O_CLOEXEC);
		if (path_fd < 0)
			continue;

		memset(&attr, 0, sizeof(attr));
		attr.parent_fd = path_fd;
		attr.allowed_access = 1 + (rand() % 0xfff);

		syscall(__NR_landlock_add_rule, ruleset_fd,
			LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
		close(path_fd);
	}
#endif
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

	arm_landlock(fd);

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
