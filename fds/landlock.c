/* landlock FD provider. */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
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

static void landlock_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "landlock fd:%d scope:%d\n",
		obj->landlockobj.fd, scope);
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
		attr.allowed_access = 1 + (rand() % 0xffff);

		syscall(__NR_landlock_add_rule, ruleset_fd,
			LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
		close(path_fd);
	}
#endif
}

/*
 * Maximum handled_access_fs bitmask per ABI version.
 *
 * Passing bits the kernel doesn't recognise causes EINVAL.  We query
 * the running kernel's ABI version and clamp to the corresponding mask
 * so ruleset creation succeeds regardless of kernel age.
 *
 * ABI v1 (5.13): bits 0–12   0x1fff
 * ABI v2 (5.19): adds REFER  0x3fff
 * ABI v3 (6.2):  adds TRUNCATE 0x7fff
 * ABI v5 (6.10): adds IOCTL_DEV 0xffff
 */
#define LANDLOCK_FS_ABI1  0x1fffULL
#define LANDLOCK_FS_ABI2  0x3fffULL
#define LANDLOCK_FS_ABI3  0x7fffULL
#define LANDLOCK_FS_ABI5  0xffffULL

/* Bytes of struct landlock_ruleset_attr valid for each ABI version.
 * ABI v1–v3 only have handled_access_fs (8 bytes).
 * ABI v4+ adds handled_access_net (16 bytes).
 * ABI v5+ adds scoped (24 bytes). */
#define LANDLOCK_ATTR_SIZE_V1  (sizeof(__u64))
#define LANDLOCK_ATTR_SIZE_V4  (sizeof(__u64) * 2)
#define LANDLOCK_ATTR_SIZE_V5  (sizeof(struct landlock_ruleset_attr))

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

static int open_landlock_fd(void)
{
#ifdef __NR_landlock_create_ruleset
	struct landlock_ruleset_attr attr;
	struct object *obj;
	size_t attr_size;
	int abi, fd;

	abi = (int)syscall(__NR_landlock_create_ruleset, NULL, 0,
			   LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 1)
		abi = 1;

	memset(&attr, 0, sizeof(attr));

	if (abi >= 5) {
		attr.handled_access_fs = LANDLOCK_FS_ABI5;
		attr_size = LANDLOCK_ATTR_SIZE_V5;
	} else if (abi >= 3) {
		attr.handled_access_fs = LANDLOCK_FS_ABI3;
		attr_size = LANDLOCK_ATTR_SIZE_V1;
	} else if (abi >= 2) {
		attr.handled_access_fs = LANDLOCK_FS_ABI2;
		attr_size = LANDLOCK_ATTR_SIZE_V1;
	} else {
		attr.handled_access_fs = LANDLOCK_FS_ABI1;
		attr_size = LANDLOCK_ATTR_SIZE_V1;
	}

	fd = syscall(__NR_landlock_create_ruleset, &attr, attr_size, 0);
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

	return open_landlock_fd();
}

static int get_rand_landlock_fd(void)
{
	struct object *obj;

	if (objects_empty(OBJ_FD_LANDLOCK) == true)
		return -1;

	obj = get_random_object(OBJ_FD_LANDLOCK, OBJ_GLOBAL);
	if (obj == NULL)
		return -1;
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
