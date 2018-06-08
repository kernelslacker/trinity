/*
 * int s390_guarded_storage(int command, struct gs_cb *gs_cb)
 */

#include <asm/guarded_storage.h>

#include "random.h"
#include "sanitise.h"

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
	freeptr(&rec->a2);
}

struct syscallentry syscall_s390_guarded_storage = {
	.name = "s390_guarded_storage",
	.sanitise = sanitise_s390_gs,
	.post = post_s390_gs,
	.num_args = 2,
	.arg1name = "command",
	.arg1type = ARG_LIST,
	.arg1list = ARGLIST(syscall_s390_guarded_storage_arg1),
	.arg2name = "gs_cb",
	.arg2type = ARG_NON_NULL_ADDRESS
};
