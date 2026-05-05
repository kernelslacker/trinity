/*
 * SYSCALL_DEFINE4(landlock_add_rule,
 *                const int, ruleset_fd, const enum landlock_rule_type, rule_type,
 *                const void __user *const, rule_attr, const __u32, flags)
 */
#include <linux/landlock.h>
#include <string.h>
#include "fd.h"
#include "random.h"
#include "sanitise.h"
#include "compat.h"

enum landlock_rule_type_compat {
	LANDLOCK_RULE_PATH_BENEATH_COMPAT = 1,
	LANDLOCK_RULE_NET_PORT_COMPAT,
};

static unsigned long landlock_ruletypes[] = {
	LANDLOCK_RULE_PATH_BENEATH_COMPAT,
	LANDLOCK_RULE_NET_PORT_COMPAT,
};

static void sanitise_landlock_add_rule(struct syscallrecord *rec)
{
	unsigned long rule_type;

	rule_type = rec->a2;

	switch (rule_type) {
	case LANDLOCK_RULE_PATH_BENEATH_COMPAT: {
		struct landlock_path_beneath_attr *pb;

		pb = (struct landlock_path_beneath_attr *) get_writable_address(sizeof(*pb));
		memset(pb, 0, sizeof(*pb));
		pb->allowed_access = rand32() & ((1ULL << 16) - 1);
		pb->parent_fd = get_random_fd();
		rec->a3 = (unsigned long) pb;
		break;
	}
	case LANDLOCK_RULE_NET_PORT_COMPAT: {
		struct landlock_net_port_attr *np;

		np = (struct landlock_net_port_attr *) get_writable_address(sizeof(*np));
		memset(np, 0, sizeof(*np));
		np->allowed_access = rand() % 4;

		switch (rand() % 4) {
		case 0: np->port = 0; break;		/* ephemeral */
		case 1: np->port = 80; break;		/* well-known */
		case 2: np->port = 1 + (rand() % 1023); break;	/* privileged */
		default: np->port = 1024 + (rand() % 64512); break; /* unprivileged */
		}
		rec->a3 = (unsigned long) np;
		break;
	}
	}

	rec->a4 = 0;	/* flags must be zero */
}

struct syscallentry syscall_landlock_add_rule = {
	.name = "landlock_add_rule",
	.num_args = 4,
	.argtype = { [0] = ARG_FD_LANDLOCK, [1] = ARG_OP },
	.argname = { [0] = "ruleset_fd", [1] = "rule_type", [2] = "rule_attr", [3] = "flags" },
	.arg_params[1].list = ARGLIST(landlock_ruletypes),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
	.sanitise = sanitise_landlock_add_rule,
};
