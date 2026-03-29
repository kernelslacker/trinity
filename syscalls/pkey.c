/*
 * SYSCALL_DEFINE2(pkey_alloc, unsigned long, flags, unsigned long, init_val)
 */

#include "sanitise.h"
#include "trinity.h"

#define PKEY_DISABLE_ACCESS     0x1
#define PKEY_DISABLE_WRITE      0x2

static unsigned long pkey_alloc_initvals[] = {
	PKEY_DISABLE_ACCESS,
	PKEY_DISABLE_WRITE,
};

static void sanitise_pkey_alloc(struct syscallrecord *rec)
{
	// no flags defined right now.
	rec->a1 = 0;
}

struct syscallentry syscall_pkey_alloc = {
	.name = "pkey_alloc",
	.num_args = 2,
	.argtype = { [1] = ARG_LIST },
	.argname = { [0] = "flags", [1] = "init_val" },
	.arg_params[1].list = ARGLIST(pkey_alloc_initvals),
	.sanitise = sanitise_pkey_alloc,
	.group = GROUP_VM,
};

struct syscallentry syscall_pkey_free = {
	.name = "pkey_free",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "key" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 15,
	.group = GROUP_VM,
};
