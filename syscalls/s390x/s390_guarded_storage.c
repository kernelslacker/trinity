/*
 * int s390_guarded_storage(int command, struct gs_cb *gs_cb)
 */

#include <asm/guarded_storage.h>

#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"

static unsigned long syscall_s390_guarded_storage_arg1[] = {
	GS_ENABLE,
	GS_DISABLE,
	GS_SET_BC_CB,
	GS_CLEAR_BC_CB,
	GS_BROADCAST,
	GS_BROADCAST + 1,
	-1
};

/* Allocate buffer and generate random data. */
static void sanitise_s390_gs(struct syscallrecord *rec)
{
	size_t size = sizeof(struct gs_cb);
	void *addr = malloc(size);

	if (addr) {
		generate_rand_bytes(addr, size);
		rec->a2 = (unsigned long)addr;
	}
}

/* Free buffer, freeptr takes care of NULL */
static void post_s390_gs(struct syscallrecord *rec)
{
	deferred_freeptr(&rec->a2);
}

struct syscallentry syscall_s390_guarded_storage = {
	.name = "s390_guarded_storage",
	.sanitise = sanitise_s390_gs,
	.post = post_s390_gs,
	.num_args = 2,
	.argtype = { [0] = ARG_LIST, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "command", [1] = "gs_cb" },
	.arg_params[0].list = ARGLIST(syscall_s390_guarded_storage_arg1),
};
