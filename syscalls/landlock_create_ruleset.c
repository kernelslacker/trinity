/*
 * SYSCALL_DEFINE3(landlock_create_ruleset,
 *                const struct landlock_ruleset_attr __user *const, attr,
 *                const size_t, size, const __u32, flags)
 */
#include "objects.h"
#include "sanitise.h"
#include "utils.h"

#define LANDLOCK_CREATE_RULESET_VERSION                 (1U << 0)

static unsigned long landlock_create_ruleset_flags[] = {
	LANDLOCK_CREATE_RULESET_VERSION,
};

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
	.arg2type = ARG_LEN,
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(landlock_create_ruleset_flags),
	.rettype = RET_FD,
	.post = post_landlock_create_ruleset,
};
