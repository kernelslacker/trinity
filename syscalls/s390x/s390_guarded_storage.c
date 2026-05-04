/*
 * int s390_guarded_storage(int command, struct gs_cb *gs_cb)
 */

#include <asm/guarded_storage.h>

#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

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

	/* Clear post_state up front so an alloc-failure path leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record. */
	rec->post_state = 0;

	if (addr) {
		generate_rand_bytes(addr, size);
		rec->a2 = (unsigned long)addr;
		/* Snapshot for the post handler -- a2 may be scribbled by a
		 * sibling syscall before post_s390_gs() runs. */
		rec->post_state = (unsigned long)addr;
	}
}

static void post_s390_gs(struct syscallrecord *rec)
{
	void *addr = (void *) rec->post_state;

	if (addr == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, addr)) {
		outputerr("post_s390_gs: rejected suspicious addr=%p (pid-scribbled?)\n", addr);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a2 = 0;
	deferred_freeptr(&rec->post_state);
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
