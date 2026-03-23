/*
 * SYSCALL_DEFINE3(landlock_create_ruleset,
 *                const struct landlock_ruleset_attr __user *const, attr,
 *                const size_t, size, const __u32, flags)
 */
#include <linux/landlock.h>
#include <string.h>
#include "objects.h"
#include "random.h"
#include "sanitise.h"

#define LANDLOCK_CREATE_RULESET_VERSION                 (1U << 0)

static unsigned long landlock_create_ruleset_flags[] = {
	LANDLOCK_CREATE_RULESET_VERSION,
};

static void sanitise_landlock_create_ruleset(struct syscallrecord *rec)
{
	struct landlock_ruleset_attr *attr;

	attr = (struct landlock_ruleset_attr *) get_writable_address(sizeof(*attr));
	memset(attr, 0, sizeof(*attr));

	/* Random combination of FS access rights. */
	attr->handled_access_fs = rand32() & ((1ULL << 16) - 1);

	/* Random combination of net access rights. */
	if (RAND_BOOL())
		attr->handled_access_net = rand() % 4;	/* 0, 1, 2, or 3 (bind|connect) */

	rec->a1 = (unsigned long) attr;
	rec->a2 = sizeof(*attr);
}

static void post_landlock_create_ruleset(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if (fd == -1)
		return;

	struct object *new = alloc_object();
	new->landlockobj.fd = fd;
	add_object(new, OBJ_LOCAL, OBJ_FD_LANDLOCK);
}

struct syscallentry syscall_landlock_create_ruleset = {
	.name = "landlock_create_ruleset",
	.num_args = 3,
	.arg1name = "attr",
	.arg2name = "size",
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(landlock_create_ruleset_flags),
	.rettype = RET_FD,
	.sanitise = sanitise_landlock_create_ruleset,
	.post = post_landlock_create_ruleset,
	.group = GROUP_PROCESS,
};
