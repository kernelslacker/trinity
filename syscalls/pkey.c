/*
 * SYSCALL_DEFINE2(pkey_alloc, unsigned long, flags, unsigned long, init_val)
 */

#include "sanitise.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"

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
	.arg1name = "flags",
	.arg2name = "init_val",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(pkey_alloc_initvals),
	.sanitise = sanitise_pkey_alloc,
	.group = GROUP_VM,
};

struct syscallentry syscall_pkey_free = {
	.name = "pkey_free",
	.num_args = 1,
	.arg1name = "key",
	.group = GROUP_VM,
};
