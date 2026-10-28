/*
 * SYSCALL_DEFINE4(landlock_add_rule,
 *                const int, ruleset_fd, const enum landlock_rule_type, rule_type,
 *                const void __user *const, rule_attr, const __u32, flags)
 */
#include <string.h>
#include "fd.h"
#include "kernel/landlock.h"
#include "kernel/sched.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

static unsigned long landlock_ruletypes[] = {
	LANDLOCK_RULE_PATH_BENEATH_COMPAT,
	LANDLOCK_RULE_NET_PORT_COMPAT,
	LANDLOCK_RULE_NAMESPACE_COMPAT,
	LANDLOCK_RULE_CAPABILITY_COMPAT,
};

/* The members a permission rule names: the namespace types (CLONE_NS_ALL in
 * the kernel) and the capabilities CAP_CHOWN..CAP_CHECKPOINT_RESTORE. */
#define LANDLOCK_NS_TYPES	(CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | \
				 CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | \
				 CLONE_NEWNET | CLONE_NEWTIME)
#define LANDLOCK_CAPS		((1ULL << 41) - 1)

/*
 * A namespace or capability rule.  The kernel answers -ENOMSG to a rule
 * with no permission or that neither allows nor quiets anything, and -EINVAL
 * to a selector other than the one its type is for or that the ruleset does
 * not handle.  Rules only ever add to the members a layer allows, and the
 * rulesets in the pool allow every member of what they handle (fds/landlock.c),
 * so the allowed mask is drawn as every member most of the time and the
 * odd draw cannot take one away.
 */
static void fill_permission_rule(struct landlock_permission_attr *pa, bool caps)
{
	__u64 members = caps ? LANDLOCK_CAPS : LANDLOCK_NS_TYPES;

	pa->permissions = caps ? LANDLOCK_PERMISSION_CAPABILITY_USE :
				 LANDLOCK_PERMISSION_NAMESPACE_USE;
	if (ONE_IN(16)) {
		switch (rnd_modulo_u32(4)) {
		case 0:
			pa->permissions = 0;
			break;
		case 1:
			pa->permissions ^= LANDLOCK_PERMISSION_NAMESPACE_USE |
					   LANDLOCK_PERMISSION_CAPABILITY_USE;
			break;
		case 2:
			pa->permissions = LANDLOCK_PERMISSION_NAMESPACE_USE |
					  LANDLOCK_PERMISSION_CAPABILITY_USE;
			break;
		default:
			pa->permissions = rand64();
			break;
		}
	}

	switch (rnd_modulo_u32(8)) {
	case 0:
		pa->allowed = 0;
		break;
	case 1:
		pa->allowed = rand64() & members;
		break;
	case 2:
		pa->allowed = rand64();
		break;
	default:
		pa->allowed = ~0ULL;
		break;
	}

	switch (rnd_modulo_u32(4)) {
	case 1:
		pa->quiet = rand64() & members;
		break;
	case 2:
		pa->quiet = rand64();
		break;
	default:
		break;
	}
}

static void sanitise_landlock_add_rule(struct syscallrecord *rec)
{
	unsigned long rule_type;
	unsigned long flags;

	rule_type = rec->a2;
	flags = rnd_modulo_u32(2) ? LANDLOCK_ADD_RULE_QUIET : 0;

	switch (rule_type) {
	case LANDLOCK_RULE_PATH_BENEATH_COMPAT: {
		struct landlock_path_beneath_attr *pb;

		pb = (struct landlock_path_beneath_attr *) get_writable_address(sizeof(*pb));
		if (pb == NULL)
			break;
		memset(pb, 0, sizeof(*pb));
		pb->allowed_access = rand32() & ((1ULL << 16) - 1);
		pb->parent_fd = get_random_fd();
		rec->a3 = (unsigned long) pb;
		avoid_shared_buffer_inout(&rec->a3, sizeof(*pb));
		break;
	}
	case LANDLOCK_RULE_NET_PORT_COMPAT: {
		struct landlock_net_port_attr *np;

		np = (struct landlock_net_port_attr *) get_writable_address(sizeof(*np));
		if (np == NULL)
			break;
		memset(np, 0, sizeof(*np));
		np->allowed_access = rnd_modulo_u32(16);

		switch (rnd_modulo_u32(4)) {
		case 0: np->port = 0; break;		/* ephemeral */
		case 1: np->port = 80; break;		/* well-known */
		case 2: np->port = 1 + (rnd_modulo_u32(1023)); break;	/* privileged */
		default: np->port = 1024 + (rnd_modulo_u32(64512)); break; /* unprivileged */
		}
		rec->a3 = (unsigned long) np;
		avoid_shared_buffer_inout(&rec->a3, sizeof(*np));
		break;
	}
	case LANDLOCK_RULE_NAMESPACE_COMPAT:
	case LANDLOCK_RULE_CAPABILITY_COMPAT: {
		struct landlock_permission_attr *pa;

		/*
		 * add_rule_namespace() and add_rule_capability() answer -EINVAL
		 * to any flag, LANDLOCK_ADD_RULE_QUIET included: the rule's own
		 * quiet mask is how they are told to stay out of the audit log.
		 */
		flags = 0;

		pa = (struct landlock_permission_attr *) get_writable_address(sizeof(*pa));
		if (pa == NULL)
			break;
		memset(pa, 0, sizeof(*pa));
		fill_permission_rule(pa, rule_type == LANDLOCK_RULE_CAPABILITY_COMPAT);
		rec->a3 = (unsigned long) pa;
		avoid_shared_buffer_inout(&rec->a3, sizeof(*pa));
		break;
	}
	}

	rec->a4 = flags;
}

struct syscallentry syscall_landlock_add_rule = {
	.name = "landlock_add_rule",
	.num_args = 4,
	.argtype = { [0] = ARG_FD_LANDLOCK, [1] = ARG_OP, [2] = ARG_ADDRESS },
	.argname = { [0] = "ruleset_fd", [1] = "rule_type", [2] = "rule_attr", [3] = "flags" },
	.arg_params[1].list = ARGLIST(landlock_ruletypes),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
	.flags = REEXEC_SANITISE_OK,
	.sanitise = sanitise_landlock_add_rule,
};
